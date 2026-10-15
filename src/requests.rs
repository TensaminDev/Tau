use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::future::Future;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use mtp::codec::{CommunicationType, CommunicationValue};
use tokio::sync::oneshot;

type Responder = Box<dyn FnOnce(Result<CommunicationValue, RequestError>) -> bool + Send + Sync>;
type Validator = std::sync::Arc<dyn Fn(&CommunicationValue) -> bool + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CorrelationError {
    #[error("invalid correlation id")]
    InvalidId,
    #[error("correlation id already occupied")]
    Occupied,
    #[error("correlation id has already been used on this transport")]
    ReusedId,
    #[error("correlation id space exhausted")]
    IdSpaceExhausted,
    #[error("correlation generation space exhausted")]
    GenerationExhausted,
    #[error("correlator closed")]
    Closed,
    #[error("correlation capacity reached")]
    Capacity,
    #[error("caller-selected and allocated IDs require separate correlators")]
    MixedIdNamespaces,
}

pub const PROTOCOL_ERROR_TYPES: &[CommunicationType] = &[
    CommunicationType::Error,
    CommunicationType::ErrorInternal,
    CommunicationType::ErrorNotFound,
    CommunicationType::ErrorInvalidData,
    CommunicationType::ErrorInvalidChallenge,
    CommunicationType::ErrorNotAuthenticated,
    CommunicationType::ErrorNoIota,
    CommunicationType::ErrorProtocol,
    CommunicationType::ErrorAnonymous,
    CommunicationType::ErrorInvalidUserId,
    CommunicationType::ErrorInvalidOmikronId,
    CommunicationType::ErrorInvalidSecret,
    CommunicationType::ErrorInvalidPrivateKey,
    CommunicationType::ErrorInvalidPublicKey,
    CommunicationType::ErrorNoUserId,
    CommunicationType::ErrorNoCallId,
    CommunicationType::ErrorInvalidCallId,
    CommunicationType::ErrorNotSet,
];

pub fn is_protocol_error(kind: CommunicationType) -> bool {
    PROTOCOL_ERROR_TYPES.contains(&kind)
}

#[derive(Clone, Debug)]
pub struct ResponseExpectation {
    pub allowed_success: Vec<CommunicationType>,
    pub allowed_errors: Vec<CommunicationType>,
}

impl ResponseExpectation {
    pub fn accepts(&self, response: &CommunicationValue) -> bool {
        response
            .type_map()
            .and_then(|map| map.comm_enum_id(response.get_type().0))
            .is_some_and(|kind| {
                self.allowed_success.contains(&kind) || self.allowed_errors.contains(&kind)
            })
    }
}

#[derive(Debug, Clone)]
pub enum RequestError {
    Registration(CorrelationError),
    Send(std::sync::Arc<dyn Error + Send + Sync>),
    Timeout,
    ConnectionClosed,
    Cancelled,
    ResponseChannelClosed,
    UnexpectedResponse,
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Registration(error) => error.fmt(f),
            Self::Send(error) => write!(f, "request send failed: {error}"),
            Self::Timeout => f.write_str("request timed out"),
            Self::ConnectionClosed => f.write_str("connection closed"),
            Self::Cancelled => f.write_str("request cancelled"),
            Self::ResponseChannelClosed => f.write_str("response channel closed"),
            Self::UnexpectedResponse => f.write_str("unexpected response type"),
        }
    }
}

impl Error for RequestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Registration(error) => Some(error),
            // Expose the concrete transport error, not the Arc wrapper.
            Self::Send(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

impl From<CorrelationError> for RequestError {
    fn from(error: CorrelationError) -> Self {
        Self::Registration(error)
    }
}

struct Correlation {
    generation: u64,
    respond: Responder,
    validator: Option<Validator>,
    inserted_at: Instant,
}

struct State {
    entries: HashMap<u32, Correlation>,
    next_id: u64,
    closed: bool,
    caller_selected: Option<bool>,
    used_ids: HashSet<u32>,
}

/// One response namespace per transport. Reserved wire IDs never wrap or reuse.
/// Mixing caller-selected IDs and allocation is rejected for the entire lifetime,
/// including after clear. Caller-selected IDs may only be used once, because
/// internal generations cannot distinguish a delayed response on the wire.
pub struct ResponseCorrelator {
    state: Mutex<State>,
    next_generation: AtomicU64,
    capacity: usize,
}

impl Default for ResponseCorrelator {
    fn default() -> Self {
        Self::with_next_id(1)
    }
}

impl ResponseCorrelator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_next_id(next: u32) -> Self {
        Self::with_capacity(next, usize::MAX)
    }

    pub fn with_capacity(next: u32, capacity: usize) -> Self {
        Self {
            state: Mutex::new(State {
                entries: HashMap::new(),
                next_id: u64::from(next.max(1)),
                closed: false,
                caller_selected: None,
                used_ids: HashSet::new(),
            }),
            next_generation: AtomicU64::new(1),
            capacity,
        }
    }

    fn insert(
        &self,
        id: Option<u32>,
        respond: Responder,
        validator: Option<Validator>,
    ) -> Result<PendingResponse<'_>, CorrelationError> {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return Err(CorrelationError::Closed);
        }
        if state.entries.len() >= self.capacity {
            return Err(CorrelationError::Capacity);
        }
        let caller_selected = id.is_some();
        if state
            .caller_selected
            .is_some_and(|mode| mode != caller_selected)
        {
            return Err(CorrelationError::MixedIdNamespaces);
        }
        let id = match id {
            Some(0) => return Err(CorrelationError::InvalidId),
            Some(id) if state.entries.contains_key(&id) => return Err(CorrelationError::Occupied),
            Some(id) if state.used_ids.contains(&id) => return Err(CorrelationError::ReusedId),
            Some(id) => id,
            None => loop {
                let id =
                    u32::try_from(state.next_id).map_err(|_| CorrelationError::IdSpaceExhausted)?;
                state.next_id += 1;
                if !state.entries.contains_key(&id) {
                    break id;
                }
            },
        };
        let generation = self
            .next_generation
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| CorrelationError::GenerationExhausted)?;
        state.entries.insert(
            id,
            Correlation {
                generation,
                respond,
                validator,
                inserted_at: Instant::now(),
            },
        );
        state.caller_selected = Some(caller_selected);
        if caller_selected {
            state.used_ids.insert(id);
        }
        Ok(PendingResponse {
            correlator: self,
            id,
            generation,
        })
    }

    /// Success-only callback API for non-relay users. Local failures drop the
    /// callback without synthesizing a peer response. Prefer exchange when the
    /// caller needs structured local failure reporting.
    pub fn reserve(
        &self,
        respond: impl FnOnce(CommunicationValue) -> bool + Send + Sync + 'static,
    ) -> Result<PendingResponse<'_>, CorrelationError> {
        self.insert(
            None,
            Box::new(move |result| result.is_ok_and(respond)),
            None,
        )
    }

    /// Like reserve, but unrelated response types leave the registration pending.
    pub fn reserve_checked(
        &self,
        respond: impl FnOnce(CommunicationValue) -> bool + Send + Sync + 'static,
        expectation: ResponseExpectation,
    ) -> Result<PendingResponse<'_>, CorrelationError> {
        self.insert(
            None,
            Box::new(move |result| result.is_ok_and(respond)),
            Some(std::sync::Arc::new(move |response| {
                expectation.accepts(response)
            })),
        )
    }

    /// Prefer reserve or exchange. Caller-selected IDs cannot be reused during
    /// this correlator's lifetime, even after cancellation or bulk cleanup.
    /// Like reserve, this compatibility callback only receives peer responses.
    pub fn register(
        &self,
        id: u32,
        respond: impl FnOnce(CommunicationValue) -> bool + Send + Sync + 'static,
    ) -> Result<PendingResponse<'_>, CorrelationError> {
        self.insert(
            Some(id),
            Box::new(move |result| result.is_ok_and(respond)),
            None,
        )
    }

    pub fn complete(&self, id: u32, response: CommunicationValue) -> bool {
        let (generation, validator) = {
            let state = self.state.lock().unwrap();
            let Some(entry) = state.entries.get(&id) else {
                return false;
            };
            (entry.generation, entry.validator.clone())
        };
        // Application validation and callbacks never run under the map lock.
        if validator.is_some_and(|validate| !validate(&response)) {
            return false;
        }
        let Some(entry) = self.detach(id, generation) else {
            return false;
        };
        (entry.respond)(Ok(response))
    }

    fn detach(&self, id: u32, generation: u64) -> Option<Correlation> {
        let mut state = self.state.lock().unwrap();
        if state
            .entries
            .get(&id)
            .is_some_and(|entry| entry.generation == generation)
        {
            state.entries.remove(&id)
        } else {
            None
        }
    }

    pub fn remove(&self, id: u32, generation: u64) -> bool {
        self.detach(id, generation).is_some()
    }

    /// Cancel exactly the registrations present at this boundary. The transport
    /// remains open; IDs remain consumed. Use close for transport shutdown.
    pub fn clear(&self) {
        self.fail_pending(RequestError::Cancelled);
    }

    pub fn retain_fresh(&self, max_age: Duration) {
        let expired: Vec<_> = {
            let state = self.state.lock().unwrap();
            state
                .entries
                .iter()
                .filter(|(_, entry)| entry.inserted_at.elapsed() >= max_age)
                .map(|(&id, entry)| (id, entry.generation))
                .collect()
        };
        for (id, generation) in expired {
            if let Some(entry) = self.detach(id, generation) {
                (entry.respond)(Err(RequestError::Timeout));
            }
        }
    }

    /// Fail the registrations present at this boundary with a local failure.
    /// Concurrent later insertions remain open and are not included.
    pub fn fail_pending(&self, error: RequestError) {
        let entries = std::mem::take(&mut self.state.lock().unwrap().entries);
        for entry in entries.into_values() {
            (entry.respond)(Err(error.clone()));
        }
    }

    /// Closing is permanent. No later registration can escape this boundary.
    pub fn close(&self) {
        let entries = {
            let mut state = self.state.lock().unwrap();
            state.closed = true;
            std::mem::take(&mut state.entries)
        };
        for entry in entries.into_values() {
            (entry.respond)(Err(RequestError::ConnectionClosed));
        }
    }

    pub fn len(&self) -> usize {
        self.state.lock().unwrap().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Reserve, send and wait using the caller's transport callback. Dropping
    /// this future removes only its registration. It does not cancel remote
    /// effects; durable operations still require application idempotency.
    pub async fn exchange<F, Fut, E>(
        &self,
        request: &CommunicationValue,
        timeout: Duration,
        validate: impl Fn(&CommunicationValue) -> bool + Send + Sync + 'static,
        send: F,
    ) -> Result<CommunicationValue, RequestError>
    where
        F: FnOnce(CommunicationValue) -> Fut,
        Fut: Future<Output = Result<(), E>>,
        E: Into<Box<dyn Error + Send + Sync>>,
    {
        let (tx, mut rx) = oneshot::channel();
        let pending = self.insert(
            None,
            Box::new(move |result| tx.send(result).is_ok()),
            Some(std::sync::Arc::new(validate)),
        )?;
        let response = tokio::time::timeout(timeout, async {
            // Local closure/cancellation must also interrupt a blocked send.
            tokio::select! {
                biased;
                result = &mut rx => return result.map_err(|_| RequestError::ResponseChannelClosed)?,
                result = send(request.clone().with_id(pending.id())) => {
                    result.map_err(|error| RequestError::Send(std::sync::Arc::from(error.into())))?;
                }
            }
            rx.await.map_err(|_| RequestError::ResponseChannelClosed)?
        })
        .await
        .map_err(|_| RequestError::Timeout)??;
        // Preserve an absent external ID rather than retaining our wire ID.
        Ok(match request.id() {
            Some(id) => response.with_id(id),
            None => response.without_id(),
        })
    }
}

#[must_use = "retain the pending response until completion or cancellation"]
pub struct PendingResponse<'a> {
    correlator: &'a ResponseCorrelator,
    id: u32,
    generation: u64,
}

impl PendingResponse<'_> {
    pub fn id(&self) -> u32 {
        self.id
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

impl Drop for PendingResponse<'_> {
    fn drop(&mut self) {
        self.correlator.remove(self.id, self.generation);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mtp::codec::CommunicationType;
    use std::sync::{Arc, Barrier};

    fn frame() -> CommunicationValue {
        CommunicationValue::new(CommunicationType::Success)
    }

    #[test]
    fn mixed_id_namespaces_remain_rejected_after_cleanup() {
        let selected = ResponseCorrelator::new();
        let pending = selected.register(1, |_| true).unwrap();
        drop(pending);
        selected.clear();
        assert!(matches!(
            selected.reserve(|_| true),
            Err(CorrelationError::MixedIdNamespaces)
        ));
        let allocated = ResponseCorrelator::new();
        drop(allocated.reserve(|_| true).unwrap());
        assert!(matches!(
            allocated.register(1, |_| true),
            Err(CorrelationError::MixedIdNamespaces)
        ));
    }

    #[test]
    fn checked_registration_keeps_waiter_after_wrong_response() {
        let correlator = ResponseCorrelator::new();
        let pending = correlator
            .reserve_checked(
                |_| true,
                ResponseExpectation {
                    allowed_success: vec![CommunicationType::AccountStateSnapshot],
                    allowed_errors: PROTOCOL_ERROR_TYPES.to_vec(),
                },
            )
            .unwrap();
        assert!(!correlator.complete(pending.id(), frame()));
        assert!(!correlator.complete(
            pending.id(),
            CommunicationValue::new(CommunicationType::AccountStateRequest)
        ));
        assert_eq!(correlator.len(), 1);
        assert!(correlator.complete(
            pending.id(),
            CommunicationValue::new(CommunicationType::ErrorNotFound)
        ));
        assert!(correlator.is_empty());
    }

    #[test]
    fn selected_ids_cannot_be_reused_after_any_cleanup_path() {
        for cleanup in 0..6 {
            let correlator = ResponseCorrelator::new();
            let old = correlator.register(42, |_| true).unwrap();
            match cleanup {
                0 => {
                    assert!(correlator.complete(42, frame()));
                }
                1 => {
                    assert!(correlator.remove(42, old.generation()));
                }
                2 => correlator.clear(),
                3 => correlator.retain_fresh(Duration::ZERO),
                4 => correlator.fail_pending(RequestError::ConnectionClosed),
                5 => correlator.fail_pending(RequestError::Cancelled),
                _ => unreachable!(),
            }
            assert!(matches!(
                correlator.register(42, |_| true),
                Err(CorrelationError::ReusedId)
            ));
            let replacement = correlator.register(43, |_| true).unwrap();
            assert_ne!(old.generation(), replacement.generation());
            drop(old);
            assert!(!correlator.complete(42, frame()));
            assert_eq!(correlator.len(), 1);
            assert!(correlator.complete(replacement.id(), frame()));
        }
    }

    #[test]
    fn registration_errors_and_counter_exhaustion_are_explicit() {
        let correlator = ResponseCorrelator::with_next_id(u32::MAX);
        assert!(matches!(
            correlator.register(0, |_| true),
            Err(CorrelationError::InvalidId)
        ));
        let last = correlator.reserve(|_| true).unwrap();
        assert_eq!(last.id(), u32::MAX);
        drop(last);
        assert!(matches!(
            correlator.reserve(|_| true),
            Err(CorrelationError::IdSpaceExhausted)
        ));
        let exhausted = ResponseCorrelator::new();
        exhausted.next_generation.store(u64::MAX, Ordering::Relaxed);
        assert!(matches!(
            exhausted.register(5, |_| true),
            Err(CorrelationError::GenerationExhausted)
        ));
        let limited = ResponseCorrelator::with_capacity(1, 0);
        assert!(matches!(
            limited.reserve(|_| true),
            Err(CorrelationError::Capacity)
        ));
    }

    #[test]
    fn simultaneous_registration_has_one_winner() {
        let correlator = ResponseCorrelator::new();
        let barrier = Barrier::new(2);
        std::thread::scope(|scope| {
            let threads: Vec<_> = (0..2)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        let pending = correlator.register(42, |_| true);
                        barrier.wait();
                        pending.is_ok()
                    })
                })
                .collect();
            assert_eq!(
                threads
                    .into_iter()
                    .map(|thread| thread.join().unwrap())
                    .filter(|won| *won)
                    .count(),
                1
            );
        });
        assert!(correlator.is_empty());
    }

    #[test]
    fn bulk_failure_callbacks_can_register_new_ids() {
        let correlator = Arc::new(ResponseCorrelator::new());
        let (tx, rx) = std::sync::mpsc::channel();
        let callback_correlator = correlator.clone();
        let old = correlator
            .insert(
                Some(42),
                Box::new(move |result| {
                    assert!(matches!(result, Err(RequestError::Cancelled)));
                    let pending = callback_correlator.register(43, |_| true).unwrap();
                    tx.send(pending.id()).unwrap();
                    true
                }),
                None,
            )
            .unwrap();
        correlator.clear();
        drop(old);
        assert_eq!(rx.recv().unwrap(), 43);
        assert!(correlator.is_empty());
    }

    #[test]
    fn completion_and_guard_drop_deliver_at_most_once() {
        for _ in 0..32 {
            let correlator = ResponseCorrelator::new();
            let count = Arc::new(AtomicU64::new(0));
            let counter = count.clone();
            let pending = correlator
                .register(42, move |_| {
                    counter.fetch_add(1, Ordering::Relaxed);
                    true
                })
                .unwrap();
            let barrier = Barrier::new(2);
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    barrier.wait();
                    correlator.complete(42, frame());
                });
                scope.spawn(|| {
                    barrier.wait();
                    drop(pending);
                });
            });
            assert!(count.load(Ordering::Relaxed) <= 1);
            assert!(correlator.is_empty());
        }
    }

    #[tokio::test]
    async fn exchange_rejects_unrelated_frames_and_restores_external_id() {
        let correlator = ResponseCorrelator::new();
        let response = correlator
            .exchange(
                &frame().with_id(42),
                Duration::from_secs(1),
                |response| response.is_type(CommunicationType::Success),
                |outbound| {
                    let correlator = &correlator;
                    async move {
                        let id = outbound.id().unwrap();
                        assert!(
                            !correlator
                                .complete(id, CommunicationValue::new(CommunicationType::Ping))
                        );
                        assert_eq!(correlator.len(), 1);
                        assert!(correlator.complete(id, frame().with_id(id)));
                        Ok::<_, String>(())
                    }
                },
            )
            .await
            .unwrap();
        assert_eq!(response.id(), Some(42));
        assert!(correlator.is_empty());
    }

    #[tokio::test]
    async fn absent_external_id_stays_absent() {
        let correlator = ResponseCorrelator::new();
        let response = correlator
            .exchange(
                &frame().without_id(),
                Duration::from_secs(1),
                |_| true,
                |outbound| {
                    correlator.complete(
                        outbound.id().unwrap(),
                        frame().with_id(outbound.id().unwrap()),
                    );
                    std::future::ready(Ok::<_, String>(()))
                },
            )
            .await
            .unwrap();
        assert_eq!(response.id(), None);
    }

    #[tokio::test]
    async fn exchange_send_failure_timeout_and_closure_clean_up() {
        let correlator = ResponseCorrelator::new();
        let failed = correlator
            .exchange(
                &frame(),
                Duration::from_secs(1),
                |_| true,
                |_| std::future::ready(Err::<(), _>("offline")),
            )
            .await;
        assert!(matches!(failed, Err(RequestError::Send(_))));
        assert!(correlator.is_empty());
        let timed_out = correlator
            .exchange(
                &frame(),
                Duration::ZERO,
                |_| true,
                |_| std::future::ready(Ok::<_, String>(())),
            )
            .await;
        assert!(matches!(timed_out, Err(RequestError::Timeout)));
        assert!(correlator.is_empty());
        let closed = correlator
            .exchange(
                &frame(),
                Duration::from_secs(1),
                |_| true,
                |_| {
                    correlator.close();
                    std::future::ready(Ok::<_, String>(()))
                },
            )
            .await;
        assert!(matches!(closed, Err(RequestError::ConnectionClosed)));
        assert!(matches!(
            correlator.reserve(|_| true),
            Err(CorrelationError::Closed)
        ));
    }

    #[tokio::test]
    async fn cancellation_never_reuses_the_cancelled_wire_id() {
        let correlator = Arc::new(ResponseCorrelator::new());
        let (sent, received) = oneshot::channel();
        let task = tokio::spawn({
            let correlator = correlator.clone();
            async move {
                correlator
                    .exchange(
                        &frame(),
                        Duration::from_secs(60),
                        |_| true,
                        |outbound| {
                            let _ = sent.send(outbound.id().unwrap());
                            std::future::ready(Ok::<_, String>(()))
                        },
                    )
                    .await
            }
        });
        let old_id = received.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(correlator.is_empty());
        let newer = correlator.reserve(|_| true).unwrap();
        assert_ne!(old_id, newer.id());
        assert!(!correlator.complete(old_id, frame()));
        assert!(correlator.complete(newer.id(), frame()));
    }

    #[test]
    fn independent_transport_namespaces_cannot_fail_each_other() {
        let old = ResponseCorrelator::new();
        let new = ResponseCorrelator::new();
        let old_request = old.reserve(|_| true).unwrap();
        let new_request = new.reserve(|_| true).unwrap();
        assert_eq!(old_request.id(), new_request.id());
        old.close();
        assert!(!old.complete(new_request.id(), frame()));
        assert_eq!(new.len(), 1);
        assert!(new.complete(new_request.id(), frame()));
    }

    #[test]
    fn validation_outside_the_lock_cannot_consume_a_replacement() {
        let correlator = ResponseCorrelator::new();
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let validator = {
            let entered = entered.clone();
            let release = release.clone();
            Arc::new(move |_: &CommunicationValue| {
                entered.wait();
                release.wait();
                true
            }) as Validator
        };
        let old = correlator
            .insert(Some(42), Box::new(|_| true), Some(validator))
            .unwrap();
        std::thread::scope(|scope| {
            let response = scope.spawn(|| correlator.complete(42, frame()));
            entered.wait();
            correlator.clear();
            let replacement = correlator.register(43, |_| true).unwrap();
            release.wait();
            assert!(!response.join().unwrap());
            drop(old);
            assert!(correlator.complete(replacement.id(), frame()));
        });
    }

    #[tokio::test]
    async fn send_failure_keeps_its_typed_source() {
        #[derive(Debug, thiserror::Error)]
        #[error("transport failed")]
        struct TransportFailure(#[source] std::io::Error);

        let correlator = ResponseCorrelator::new();
        let error = correlator
            .exchange(
                &frame(),
                Duration::from_secs(1),
                |_| true,
                |_| {
                    std::future::ready(Err::<(), _>(TransportFailure(std::io::Error::from(
                        std::io::ErrorKind::ConnectionReset,
                    ))))
                },
            )
            .await
            .unwrap_err();
        let source = error.source().unwrap();
        let transport = source.downcast_ref::<TransportFailure>().unwrap();
        assert_eq!(transport.0.kind(), std::io::ErrorKind::ConnectionReset);
        assert!(source.source().unwrap().is::<std::io::Error>());
        assert!(matches!(error, RequestError::Send(_)));
        assert!(correlator.is_empty());
    }

    #[tokio::test]
    async fn local_cleanup_returns_structured_errors_and_remains_open() {
        for clear in [true, false] {
            let correlator = ResponseCorrelator::new();
            let error = correlator
                .exchange(
                    &frame(),
                    Duration::from_secs(1),
                    |_| true,
                    |_| {
                        if clear {
                            correlator.clear();
                        } else {
                            correlator.fail_pending(RequestError::Timeout);
                        }
                        std::future::ready(Ok::<_, String>(()))
                    },
                )
                .await
                .unwrap_err();
            assert!(matches!(
                (clear, error),
                (true, RequestError::Cancelled) | (false, RequestError::Timeout)
            ));
            assert!(correlator.reserve(|_| true).is_ok());
        }
    }

    #[tokio::test]
    async fn close_interrupts_a_blocked_send() {
        let correlator = Arc::new(ResponseCorrelator::new());
        let (sending, started) = oneshot::channel();
        let task = tokio::spawn({
            let correlator = correlator.clone();
            async move {
                correlator
                    .exchange(
                        &frame(),
                        Duration::from_secs(60),
                        |_| true,
                        |_| async {
                            sending.send(()).unwrap();
                            std::future::pending::<Result<(), String>>().await
                        },
                    )
                    .await
            }
        });
        started.await.unwrap();
        correlator.close();
        let result = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(RequestError::ConnectionClosed)));
        assert!(correlator.is_empty());
    }
}
