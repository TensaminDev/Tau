use std::{future::Future, pin::Pin, sync::Arc};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::*;

pub type CallFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, CallError>> + Send + 'a>>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinRequest {
    pub call: CallId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinGrant {
    pub call: CallId,
    pub revision: u64,
    pub media_endpoint: String,
    pub credential: String,
    pub expires_at_ms: i64,
    pub permissions: EffectivePermissions,
}

pub trait CallManagement: Send + Sync {
    fn execute(
        &self,
        actor: AuthenticatedCallActor,
        request: CallCommandRequest,
    ) -> CallFuture<'_, CallCommandResult>;
    fn snapshot(&self, actor: AuthenticatedCallActor, call: CallId)
    -> CallFuture<'_, CallSnapshot>;
    fn authorize_join(
        &self,
        actor: AuthenticatedCallActor,
        request: JoinRequest,
    ) -> CallFuture<'_, JoinGrant>;
}

pub trait CallClock: Send + Sync {
    fn now_ms(&self) -> Result<i64, CallError>;
}

pub struct SystemCallClock;
impl CallClock for SystemCallClock {
    fn now_ms(&self) -> Result<i64, CallError> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_millis()).ok())
            .ok_or(CallError::StorageUnavailable)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingCallEffect {
    pub id: Uuid,
    pub call: CallId,
    pub revision: u64,
    pub effect: CallEffect,
    pub claim_generation: u64,
    pub attempts: u32,
}

pub trait CallRepository: Send + Sync {
    /// Under a single write transaction: deduplicate by call/actor/operation,
    /// reject conflicting request bytes, invoke `transition`, then persist its
    /// state, audit, events, effects and result atomically. Check duplicates
    /// before revision or membership, so retries after revocation still work.
    /// Implementations must move blocking database work off the async executor.
    fn transact(
        &self,
        actor: AuthenticatedCallActor,
        request: CallCommandRequest,
        now_ms: i64,
    ) -> CallFuture<'_, CallCommandResult>;
    fn read(&self, call: CallId) -> CallFuture<'_, Call>;
    fn next_key_epoch(&self, call: CallId) -> CallFuture<'_, u64> {
        Box::pin(async move {
            self.read(call)
                .await?
                .key_epoch
                .checked_add(1)
                .ok_or(CallError::KeyEpochPending)
        })
    }
    /// Persist the admission window before returning a minted credential.
    /// Recheck the authoritative revision and membership in this transaction.
    fn record_join_credential(
        &self,
        call: CallId,
        principal: CallPrincipal,
        revision: u64,
        expires_at_ms: i64,
        now_ms: i64,
    ) -> CallFuture<'_, ()>;
    fn enforcement_status(&self, _call: CallId) -> CallFuture<'_, EnforcementStatus> {
        Box::pin(async { Ok(EnforcementStatus::PendingEnforcement) })
    }
    /// Claims with a lease. Each reclaim increments claim_generation.
    fn claim_effects(&self, now_ms: i64, limit: usize) -> CallFuture<'_, Vec<PendingCallEffect>>;
    /// Persist any prepared target binding, fence stale claim generations, and
    /// renew the lease before executing an external effect.
    fn prepare_claim(
        &self,
        claim: PendingCallEffect,
        effect: CallEffect,
        now_ms: i64,
    ) -> CallFuture<'_, PendingCallEffect>;
    /// Acknowledge only the claimed generation. Failed work is retried with backoff.
    fn finish_effect(
        &self,
        claim: PendingCallEffect,
        outcome: Result<(), CallError>,
        now_ms: i64,
    ) -> CallFuture<'_, ()>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaCapabilities {
    pub source_permissions: bool,
    pub deny_receive_media: bool,
    pub mute_microphone_track: bool,
    pub immediate_credential_revocation: bool,
}

pub trait MediaController: Send + Sync {
    fn capabilities(&self) -> MediaCapabilities;
    fn prepare(&self, _call: Call, effect: CallEffect) -> CallFuture<'_, CallEffect> {
        Box::pin(async move { Ok(effect) })
    }
    /// Reconcile the latest aggregate, not the effect's historical projection.
    /// The adapter serializes participant operations and checks session generation.
    fn apply(&self, call: Call, effect: CallEffect, now_ms: i64) -> CallFuture<'_, ()>;
    /// Must mint locally without external awaits after the authorization read.
    fn issue_join_credential(
        &self,
        call: &Call,
        principal: &CallPrincipal,
        permissions: EffectivePermissions,
        now_ms: i64,
    ) -> Result<JoinGrant, CallError>;
}

pub trait CallEventPublisher: Send + Sync {
    /// Recheck audience eligibility before sending. A removed notice is the
    /// only event deliverable to a no-longer-authorized principal.
    fn publish(&self, current: Call, event: CallEvent) -> CallFuture<'_, ()>;
}

pub trait CallEnvelopeDirectory: Send + Sync {
    /// Ciphertext only. Completion includes durable saga progress at the owner.
    fn apply(&self, current: Call, effect: CallEffect) -> CallFuture<'_, ()>;
}

pub struct CallEngine {
    repository: Arc<dyn CallRepository>,
    media: Arc<dyn MediaController>,
    events: Arc<dyn CallEventPublisher>,
    envelopes: Arc<dyn CallEnvelopeDirectory>,
    clock: Arc<dyn CallClock>,
    operation_gates: tokio::sync::Mutex<
        std::collections::BTreeMap<CallId, std::sync::Weak<tokio::sync::Mutex<()>>>,
    >,
}

impl CallEngine {
    pub fn new(
        repository: Arc<dyn CallRepository>,
        media: Arc<dyn MediaController>,
        events: Arc<dyn CallEventPublisher>,
        envelopes: Arc<dyn CallEnvelopeDirectory>,
        clock: Arc<dyn CallClock>,
    ) -> Self {
        Self {
            repository,
            media,
            events,
            envelopes,
            clock,
            operation_gates: tokio::sync::Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    async fn lock_call(&self, call: &CallId) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut gates = self.operation_gates.lock().await;
            gates.retain(|_, weak| weak.strong_count() > 0);
            let weak = gates.entry(call.clone()).or_default();
            match weak.upgrade() {
                Some(lock) => lock,
                None => {
                    let lock = Arc::new(tokio::sync::Mutex::new(()));
                    *weak = Arc::downgrade(&lock);
                    lock
                }
            }
        };
        lock.lock_owned().await
    }

    /// Hosts drive this from a bounded worker and on startup. Delivery is at
    /// least once; a lost response must be reconciled rather than assumed failed.
    pub async fn process_effects(&self, limit: usize) -> Result<usize, CallError> {
        if limit == 0 || limit > 1024 {
            return Err(CallError::InvalidRequest);
        }
        let mut count = 0;
        for _ in 0..limit {
            let Some(mut claim) = self
                .repository
                .claim_effects(self.clock.now_ms()?, 1)
                .await?
                .pop()
            else {
                break;
            };
            count += 1;
            let _guard = self.lock_call(&claim.call).await;
            let current = self.repository.read(claim.call.clone()).await;
            if matches!(&claim.effect, CallEffect::MuteMicrophoneNow { .. }) {
                if let Ok(call) = &current {
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(20),
                        self.media.prepare(call.clone(), claim.effect.clone()),
                    )
                    .await
                    {
                        Ok(Ok(effect)) => {
                            claim = self
                                .repository
                                .prepare_claim(claim, effect, self.clock.now_ms()?)
                                .await?
                        }
                        result => {
                            let error = match result {
                                Ok(Err(error)) => error,
                                _ => CallError::MediaEnforcementPending,
                            };
                            self.repository
                                .finish_effect(claim, Err(error), self.clock.now_ms()?)
                                .await?;
                            continue;
                        }
                    }
                }
            } else {
                let effect = claim.effect.clone();
                claim = self
                    .repository
                    .prepare_claim(claim, effect, self.clock.now_ms()?)
                    .await?;
            }
            let dispatch = async {
                match current {
                    Err(error) => Err(error),
                    Ok(current) => match &claim.effect {
                        CallEffect::Publish { event } => {
                            self.events.publish(current, event.clone()).await
                        }
                        CallEffect::StageInvitation { .. }
                        | CallEffect::RevokeEnvelopes { .. }
                        | CallEffect::RevokeEnvelopesThrough { .. }
                        | CallEffect::RequestKeyRotation { .. }
                        | CallEffect::RevokeLinks => {
                            self.envelopes.apply(current, claim.effect.clone()).await
                        }
                        _ => {
                            self.media
                                .apply(current, claim.effect.clone(), self.clock.now_ms()?)
                                .await
                        }
                    },
                }
            };
            let outcome = tokio::time::timeout(std::time::Duration::from_secs(20), dispatch)
                .await
                .unwrap_or(Err(CallError::MediaEnforcementPending));
            self.repository
                .finish_effect(claim, outcome, self.clock.now_ms()?)
                .await?;
        }
        Ok(count)
    }
}

impl CallManagement for CallEngine {
    fn execute(
        &self,
        actor: AuthenticatedCallActor,
        request: CallCommandRequest,
    ) -> CallFuture<'_, CallCommandResult> {
        Box::pin(async move {
            let _guard = self.lock_call(&request.call).await;
            request.validate()?;
            match &request.command {
                CallCommand::MuteMicrophoneNow { .. }
                | CallCommand::MuteAllMicrophonesNow { .. }
                    if !self.media.capabilities().mute_microphone_track =>
                {
                    return Err(CallError::UnsupportedMediaCapability);
                }
                CallCommand::SetMemberRestriction {
                    restriction: MemberRestriction::Soundboard,
                    ..
                } => return Err(CallError::UnsupportedMediaCapability),
                CallCommand::SetMemberRestriction {
                    restriction: MemberRestriction::ServerDeafened,
                    ..
                } if !self.media.capabilities().deny_receive_media
                    || !self.media.capabilities().source_permissions =>
                {
                    return Err(CallError::UnsupportedMediaCapability);
                }
                CallCommand::SetMemberOverride {
                    permission: MemberPermission::ReceiveMedia,
                    ..
                } if !self.media.capabilities().deny_receive_media => {
                    return Err(CallError::UnsupportedMediaCapability);
                }
                CallCommand::SetMemberRestriction { .. }
                | CallCommand::SetMemberOverride { .. }
                | CallCommand::SetRole { .. }
                | CallCommand::TransferOwnership { .. }
                | CallCommand::SetPolicy {
                    change:
                        CallPolicyChange::Speak(_)
                        | CallPolicyChange::Camera(_)
                        | CallPolicyChange::ScreenShare(_)
                        | CallPolicyChange::PublishData(_)
                        | CallPolicyChange::GuestMicrophone(_)
                        | CallPolicyChange::GuestScreenShare(_)
                        | CallPolicyChange::NewMembersMuted(_),
                } if !self.media.capabilities().source_permissions => {
                    return Err(CallError::UnsupportedMediaCapability);
                }
                _ => {}
            }
            self.repository
                .transact(actor, request, self.clock.now_ms()?)
                .await
        })
    }

    fn snapshot(
        &self,
        actor: AuthenticatedCallActor,
        call: CallId,
    ) -> CallFuture<'_, CallSnapshot> {
        Box::pin(async move {
            let mut snapshot = self
                .repository
                .read(call.clone())
                .await?
                .snapshot(&actor, self.clock.now_ms()?)?;
            snapshot.enforcement = self.repository.enforcement_status(call).await?;
            snapshot.next_key_epoch = self
                .repository
                .next_key_epoch(snapshot.call.clone())
                .await?;
            Ok(snapshot)
        })
    }

    fn authorize_join(
        &self,
        actor: AuthenticatedCallActor,
        request: JoinRequest,
    ) -> CallFuture<'_, JoinGrant> {
        Box::pin(async move {
            let _guard = self.lock_call(&request.call).await;
            let call = self.repository.read(request.call).await?;
            let now_ms = self.clock.now_ms()?;
            call.snapshot(&actor, now_ms)?;
            if call.terminal() {
                return Err(CallError::AlreadyEnded);
            }
            if call.banned(actor.principal()) {
                return Err(CallError::Banned);
            }
            let member = call
                .member(actor.principal())
                .filter(|m| m.authorized)
                .ok_or(CallError::NotMember)?;
            if let Some(until_ms) = member.timeout_until_ms.filter(|until| *until > now_ms) {
                return Err(CallError::TimedOut { until_ms });
            }
            let effective = permissions(&call, actor.principal(), now_ms);
            if !effective.join {
                return Err(CallError::CallLocked);
            }
            let grant =
                self.media
                    .issue_join_credential(&call, actor.principal(), effective, now_ms)?;
            self.repository
                .record_join_credential(
                    call.id.clone(),
                    actor.principal().clone(),
                    call.revision,
                    grant.expires_at_ms,
                    now_ms,
                )
                .await?;
            Ok(grant)
        })
    }
}
