use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, Ordering},
    },
};

use tau::calls::{
    conformance::{CallManagementFixture, call_management_conformance},
    *,
};
use uuid::Uuid;

struct Clock(AtomicI64);

impl CallClock for Clock {
    fn now_ms(&self) -> Result<i64, CallError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

struct Work {
    claim: PendingCallEffect,
    available_at: i64,
    leased_until: i64,
}

struct Store {
    call: Call,
    operations: BTreeMap<(CallPrincipal, Uuid), (CallCommandRequest, CallCommandResult)>,
    audit: Vec<CallTransition>,
    effects: Vec<Work>,
    credentials: Vec<(CallPrincipal, i64)>,
}

struct Repository(Mutex<Store>);

impl CallRepository for Repository {
    fn transact(
        &self,
        actor: AuthenticatedCallActor,
        request: CallCommandRequest,
        now_ms: i64,
    ) -> CallFuture<'_, CallCommandResult> {
        Box::pin(async move {
            let mut store = self.0.lock().unwrap();
            if request.call != store.call.id {
                return Err(CallError::NotFound);
            }
            let key = (actor.principal().clone(), request.operation_id);
            if let Some((original, result)) = store.operations.get(&key) {
                return if *original == request {
                    Ok(result.clone())
                } else {
                    Err(CallError::OperationConflict)
                };
            }
            let transition = transition(&store.call, &actor, &request, now_ms)?;
            let result = CallCommandResult {
                revision: transition.call.revision,
                status: EnforcementStatus::PendingEnforcement,
                rotation_required: transition.call.rotation_required,
            };
            for effect in &transition.effects {
                store.effects.push(Work {
                    claim: PendingCallEffect {
                        id: Uuid::new_v4(),
                        call: request.call.clone(),
                        revision: result.revision,
                        effect: effect.clone(),
                        claim_generation: 0,
                        attempts: 0,
                    },
                    available_at: now_ms,
                    leased_until: 0,
                });
            }
            store.call = transition.call.clone();
            store.audit.push(transition);
            store.operations.insert(key, (request, result.clone()));
            Ok(result)
        })
    }

    fn read(&self, call: CallId) -> CallFuture<'_, Call> {
        Box::pin(async move {
            let store = self.0.lock().unwrap();
            if call != store.call.id {
                return Err(CallError::NotFound);
            }
            Ok(store.call.clone())
        })
    }

    fn record_join_credential(
        &self,
        call: CallId,
        principal: CallPrincipal,
        revision: u64,
        expires_at_ms: i64,
        now_ms: i64,
    ) -> CallFuture<'_, ()> {
        Box::pin(async move {
            let mut store = self.0.lock().unwrap();
            if call != store.call.id {
                return Err(CallError::NotFound);
            }
            if revision != store.call.revision {
                return Err(CallError::Conflict {
                    current_revision: store.call.revision,
                });
            }
            if !store.call.is_admitted(&principal, now_ms)
                || !permissions(&store.call, &principal, now_ms).join
            {
                return Err(CallError::NotAuthorized);
            }
            if expires_at_ms <= now_ms {
                return Err(CallError::InvalidRequest);
            }
            store.credentials.push((principal, expires_at_ms));
            Ok(())
        })
    }

    fn enforcement_status(&self, call: CallId) -> CallFuture<'_, EnforcementStatus> {
        Box::pin(async move {
            let store = self.0.lock().unwrap();
            if call != store.call.id {
                return Err(CallError::NotFound);
            }
            Ok(if store.effects.is_empty() {
                EnforcementStatus::Applied
            } else {
                EnforcementStatus::PendingEnforcement
            })
        })
    }

    fn claim_effects(&self, now_ms: i64, limit: usize) -> CallFuture<'_, Vec<PendingCallEffect>> {
        Box::pin(async move {
            let mut store = self.0.lock().unwrap();
            Ok(store
                .effects
                .iter_mut()
                .filter(|work| work.available_at <= now_ms && work.leased_until <= now_ms)
                .take(limit)
                .map(|work| {
                    work.claim.claim_generation += 1;
                    work.claim.attempts += 1;
                    work.leased_until = now_ms + 30_000;
                    work.claim.clone()
                })
                .collect())
        })
    }

    fn prepare_claim(
        &self,
        claim: PendingCallEffect,
        effect: CallEffect,
        now_ms: i64,
    ) -> CallFuture<'_, PendingCallEffect> {
        Box::pin(async move {
            let mut store = self.0.lock().unwrap();
            let work = store
                .effects
                .iter_mut()
                .find(|work| {
                    work.claim.id == claim.id
                        && work.claim.claim_generation == claim.claim_generation
                        && work.leased_until > now_ms
                })
                .ok_or(CallError::StorageUnavailable)?;
            work.claim.effect = effect;
            work.leased_until = now_ms + 30_000;
            Ok(work.claim.clone())
        })
    }

    fn finish_effect(
        &self,
        claim: PendingCallEffect,
        outcome: Result<(), CallError>,
        now_ms: i64,
    ) -> CallFuture<'_, ()> {
        Box::pin(async move {
            let mut store = self.0.lock().unwrap();
            let index = store
                .effects
                .iter()
                .position(|work| {
                    work.claim.id == claim.id
                        && work.claim.claim_generation == claim.claim_generation
                        && work.leased_until > now_ms
                })
                .ok_or(CallError::StorageUnavailable)?;
            if outcome.is_ok() {
                store.effects.remove(index);
            } else {
                let work = &mut store.effects[index];
                work.available_at = now_ms + 1_000;
                work.leased_until = 0;
            }
            Ok(())
        })
    }
}

#[derive(Clone, Copy)]
enum Fault {
    Success,
    Timeout,
    Unsupported,
    LostResponse,
    Hang,
}

struct Media {
    capabilities: MediaCapabilities,
    fault: Mutex<Fault>,
    applied: Mutex<BTreeMap<CallPrincipal, EffectivePermissions>>,
    muted: Mutex<Vec<CallEffect>>,
}

impl MediaController for Media {
    fn capabilities(&self) -> MediaCapabilities {
        self.capabilities
    }

    fn prepare(&self, _call: Call, effect: CallEffect) -> CallFuture<'_, CallEffect> {
        Box::pin(async move {
            Ok(match effect {
                CallEffect::MuteMicrophoneNow { principal } => CallEffect::BoundMicrophoneMute {
                    principal,
                    participant_sid: "session-1".into(),
                    track_sids: vec!["microphone-1".into()],
                },
                effect => effect,
            })
        })
    }

    fn apply(&self, call: Call, effect: CallEffect, now_ms: i64) -> CallFuture<'_, ()> {
        Box::pin(async move {
            let fault = std::mem::replace(&mut *self.fault.lock().unwrap(), Fault::Success);
            match fault {
                Fault::Hang => tokio::time::sleep(std::time::Duration::from_secs(60)).await,
                Fault::Timeout => return Err(CallError::MediaEnforcementPending),
                Fault::Unsupported => return Err(CallError::UnsupportedMediaCapability),
                _ => {}
            }
            match effect {
                CallEffect::ReconcileMember { principal }
                | CallEffect::RemoveMember { principal } => {
                    self.applied
                        .lock()
                        .unwrap()
                        .insert(principal.clone(), permissions(&call, &principal, now_ms));
                }
                CallEffect::BoundMicrophoneMute { .. } => {
                    let mut muted = self.muted.lock().unwrap();
                    if !muted.contains(&effect) {
                        muted.push(effect);
                    }
                }
                _ => {}
            }
            if matches!(fault, Fault::LostResponse) {
                Err(CallError::MediaEnforcementPending)
            } else {
                Ok(())
            }
        })
    }

    fn issue_join_credential(
        &self,
        call: &Call,
        _principal: &CallPrincipal,
        permissions: EffectivePermissions,
        now_ms: i64,
    ) -> Result<JoinGrant, CallError> {
        Ok(JoinGrant {
            call: call.id.clone(),
            revision: call.revision,
            media_endpoint: "fake://media".into(),
            credential: "test-only".into(),
            expires_at_ms: now_ms + 60_000,
            permissions,
        })
    }
}

#[derive(Default)]
struct Events(Mutex<Vec<CallEvent>>);

impl CallEventPublisher for Events {
    fn publish(&self, current: Call, mut event: CallEvent) -> CallFuture<'_, ()> {
        Box::pin(async move {
            if event.kind != CallEventKind::Removed {
                event.audience.retain(|principal| {
                    current.member(principal).is_some_and(|m| m.authorized)
                        && !current.banned(principal)
                });
            }
            let mut events = self.0.lock().unwrap();
            if !events.contains(&event) {
                events.push(event);
            }
            Ok(())
        })
    }
}

#[derive(Default)]
struct Envelopes(Mutex<Vec<CallEffect>>);

impl CallEnvelopeDirectory for Envelopes {
    fn apply(&self, _current: Call, effect: CallEffect) -> CallFuture<'_, ()> {
        Box::pin(async move {
            let mut effects = self.0.lock().unwrap();
            if !effects.contains(&effect) {
                effects.push(effect);
            }
            Ok(())
        })
    }
}

struct Backend {
    fixture: CallManagementFixture,
    engine: Arc<CallEngine>,
    repository: Arc<Repository>,
    media: Arc<Media>,
    events: Arc<Events>,
    envelopes: Arc<Envelopes>,
    clock: Arc<Clock>,
}

fn backend(capabilities: MediaCapabilities) -> Backend {
    let authority = CallAuthority::new("omega:conformance.invalid".into()).unwrap();
    let actors: Vec<_> = (1..=5)
        .map(|user_id| {
            AuthenticatedCallActor::from_verified_session(CallPrincipal {
                authority: authority.clone(),
                user_id,
            })
            .unwrap()
        })
        .collect();
    let call = Call {
        id: CallId {
            owner_authority: authority,
            id: Uuid::new_v4(),
        },
        owner: actors[0].principal().clone(),
        lifecycle: CallLifecycle::Active,
        revision: 0,
        policy: CallPolicy {
            locked: false,
            allow_locked_rejoin: true,
            join_policy: JoinPolicy::Invited,
            invite: RolePolicy::All,
            speak: RolePolicy::All,
            camera: RolePolicy::All,
            screen_share: RolePolicy::All,
            publish_data: RolePolicy::All,
            new_members_muted: false,
            guest_microphone: false,
            guest_screen_share: false,
            moderators_may_end: false,
            moderators_may_change_policy: false,
            moderators: ModeratorPermissions::default(),
            max_members: 20,
            max_invites: 20,
            invite_ttl_ms: 60_000,
            empty_grace_ms: 0,
        },
        members: actors[..4]
            .iter()
            .enumerate()
            .map(|(index, actor)| CallMember {
                principal: actor.principal().clone(),
                role: match index {
                    0 => CallRole::Owner,
                    1 | 3 => CallRole::Moderator,
                    _ => CallRole::Member,
                },
                authorized: true,
                approved: true,
                guest: false,
                restrictions: Restrictions::default(),
                overrides: PermissionOverrides::default(),
                timeout_until_ms: None,
            })
            .collect(),
        invitations: vec![],
        bans: vec![],
        key_epoch: 1,
        rotation_required: false,
        rotation_generation: 0,
        key_available_generation: 0,
        key_installations: vec![],
    };
    call.validate().unwrap();
    let id = call.id.clone();
    let repository = Arc::new(Repository(Mutex::new(Store {
        call,
        operations: BTreeMap::new(),
        audit: vec![],
        effects: vec![],
        credentials: vec![],
    })));
    let media = Arc::new(Media {
        capabilities,
        fault: Mutex::new(Fault::Success),
        applied: Mutex::new(BTreeMap::new()),
        muted: Mutex::new(vec![]),
    });
    let events = Arc::new(Events::default());
    let envelopes = Arc::new(Envelopes::default());
    let clock = Arc::new(Clock(AtomicI64::new(1_000_000)));
    let engine = Arc::new(CallEngine::new(
        repository.clone(),
        media.clone(),
        events.clone(),
        envelopes.clone(),
        clock.clone(),
    ));
    Backend {
        fixture: CallManagementFixture {
            management: engine.clone(),
            call: id,
            owner: actors[0].clone(),
            moderator: actors[1].clone(),
            member: actors[2].clone(),
            other_moderator: actors[3].clone(),
            outsider: actors[4].clone(),
        },
        engine,
        repository,
        media,
        events,
        envelopes,
        clock,
    }
}

fn supported() -> MediaCapabilities {
    MediaCapabilities {
        source_permissions: true,
        deny_receive_media: true,
        mute_microphone_track: true,
        immediate_credential_revocation: true,
    }
}

fn request(f: &CallManagementFixture, command: CallCommand) -> CallCommandRequest {
    CallCommandRequest {
        call: f.call.clone(),
        operation_id: Uuid::new_v4(),
        expected_revision: None,
        command,
    }
}

#[tokio::test]
async fn reference_backend_conforms() {
    call_management_conformance(|| async { Ok(backend(supported()).fixture) }).await;
}

#[tokio::test]
async fn effects_reconcile_after_timeout_unsupported_and_lost_response() {
    for fault in [
        Fault::Success,
        Fault::Timeout,
        Fault::Unsupported,
        Fault::LostResponse,
    ] {
        let b = backend(supported());
        let f = &b.fixture;
        *b.media.fault.lock().unwrap() = fault;
        let target = f.member.principal().clone();
        let command = request(
            f,
            CallCommand::SetMemberRestriction {
                target: target.clone(),
                restriction: MemberRestriction::Microphone,
                enabled: true,
            },
        );
        let committed = b
            .engine
            .execute(f.owner.clone(), command.clone())
            .await
            .unwrap();
        b.engine.process_effects(100).await.unwrap();
        if !matches!(fault, Fault::Success) {
            assert_eq!(
                b.engine
                    .snapshot(f.owner.clone(), f.call.clone())
                    .await
                    .unwrap()
                    .enforcement,
                EnforcementStatus::PendingEnforcement
            );
            assert_eq!(
                b.media.applied.lock().unwrap().contains_key(&target),
                matches!(fault, Fault::LostResponse)
            );
        }
        // A newer aggregate supersedes the historical failed restriction effect.
        b.engine
            .execute(
                f.owner.clone(),
                request(
                    f,
                    CallCommand::SetMemberRestriction {
                        target: target.clone(),
                        restriction: MemberRestriction::Microphone,
                        enabled: false,
                    },
                ),
            )
            .await
            .unwrap();
        b.clock.0.fetch_add(1_000, Ordering::SeqCst);
        b.engine.process_effects(100).await.unwrap();
        assert!(b.media.applied.lock().unwrap()[&target].publish_microphone);
        assert_eq!(
            b.engine
                .snapshot(f.member.clone(), f.call.clone())
                .await
                .unwrap()
                .enforcement,
            EnforcementStatus::Applied
        );
        assert_eq!(
            b.engine.execute(f.owner.clone(), command).await.unwrap(),
            committed
        );
        let store = b.repository.0.lock().unwrap();
        assert_eq!(store.audit.len(), 2);
        assert_eq!(store.call.revision, 2);
        assert!(store.effects.is_empty());
        assert_eq!(b.events.0.lock().unwrap().len(), 2);
    }
}

#[tokio::test]
async fn capabilities_reject_before_commit_and_credentials_are_recorded() {
    let b = backend(MediaCapabilities::default());
    let f = &b.fixture;
    for command in [
        CallCommand::MuteMicrophoneNow {
            target: f.member.principal().clone(),
        },
        CallCommand::SetMemberRestriction {
            target: f.member.principal().clone(),
            restriction: MemberRestriction::ServerDeafened,
            enabled: true,
        },
        CallCommand::SetMemberRestriction {
            target: f.member.principal().clone(),
            restriction: MemberRestriction::Soundboard,
            enabled: true,
        },
    ] {
        assert_eq!(
            b.engine.execute(f.owner.clone(), request(f, command)).await,
            Err(CallError::UnsupportedMediaCapability)
        );
    }
    let grant = b
        .engine
        .authorize_join(
            f.member.clone(),
            JoinRequest {
                call: f.call.clone(),
            },
        )
        .await
        .unwrap();
    let store = b.repository.0.lock().unwrap();
    assert_eq!(store.call.revision, 0);
    assert!(store.audit.is_empty() && store.effects.is_empty());
    assert_eq!(
        store.credentials,
        vec![(f.member.principal().clone(), grant.expires_at_ms)]
    );
}

#[tokio::test]
async fn removed_actor_retry_does_not_duplicate_outbox_and_events_conceal_state() {
    let b = backend(supported());
    let f = &b.fixture;
    let leave = request(f, CallCommand::Leave);
    let result = b
        .engine
        .execute(f.member.clone(), leave.clone())
        .await
        .unwrap();
    assert_eq!(
        b.engine.execute(f.member.clone(), leave).await.unwrap(),
        result
    );
    b.engine.process_effects(100).await.unwrap();
    assert_eq!(b.repository.0.lock().unwrap().audit.len(), 1);
    let events = b.events.0.lock().unwrap();
    assert!(
        events
            .iter()
            .any(|event| event.kind == CallEventKind::Removed
                && event.audience == vec![f.member.principal().clone()])
    );
    assert!(
        events
            .iter()
            .filter(|event| event.kind != CallEventKind::Removed)
            .all(|event| !event.audience.contains(f.member.principal())
                && !event.audience.contains(f.outsider.principal()))
    );
    let envelopes = b.envelopes.0.lock().unwrap();
    assert!(envelopes.contains(&CallEffect::RevokeEnvelopes {
        principal: f.member.principal().clone()
    }));
    assert!(envelopes.contains(&CallEffect::RequestKeyRotation { generation: 1 }));
}

#[tokio::test]
async fn bound_one_shot_mute_survives_lost_response() {
    let b = backend(supported());
    let f = &b.fixture;
    *b.media.fault.lock().unwrap() = Fault::LostResponse;
    b.engine
        .execute(
            f.owner.clone(),
            request(
                f,
                CallCommand::MuteMicrophoneNow {
                    target: f.member.principal().clone(),
                },
            ),
        )
        .await
        .unwrap();
    b.engine.process_effects(100).await.unwrap();
    assert!(matches!(
        b.repository.0.lock().unwrap().effects[0].claim.effect,
        CallEffect::BoundMicrophoneMute { .. }
    ));
    b.clock.0.fetch_add(1_000, Ordering::SeqCst);
    b.engine.process_effects(100).await.unwrap();
    assert_eq!(b.media.muted.lock().unwrap().len(), 1);
    assert!(
        b.engine
            .snapshot(f.member.clone(), f.call.clone())
            .await
            .unwrap()
            .permissions
            .publish_microphone
    );
    assert!(b.repository.0.lock().unwrap().effects.is_empty());
}

#[tokio::test]
async fn hung_media_is_bounded_and_retried() {
    let b = backend(supported());
    let f = &b.fixture;
    *b.media.fault.lock().unwrap() = Fault::Hang;
    b.engine
        .execute(
            f.owner.clone(),
            request(
                f,
                CallCommand::SetMemberRestriction {
                    target: f.member.principal().clone(),
                    restriction: MemberRestriction::Microphone,
                    enabled: true,
                },
            ),
        )
        .await
        .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(25),
        b.engine.process_effects(100),
    )
    .await
    .expect("engine must bound external awaits")
    .unwrap();
    assert_eq!(
        b.engine
            .snapshot(f.owner.clone(), f.call.clone())
            .await
            .unwrap()
            .enforcement,
        EnforcementStatus::PendingEnforcement
    );
    b.clock.0.fetch_add(1_000, Ordering::SeqCst);
    b.engine.process_effects(100).await.unwrap();
    assert_eq!(
        b.engine
            .snapshot(f.owner.clone(), f.call.clone())
            .await
            .unwrap()
            .enforcement,
        EnforcementStatus::Applied
    );
}

#[tokio::test]
async fn stale_claims_and_join_revisions_are_fenced() {
    let b = backend(supported());
    let f = &b.fixture;
    let now = b.clock.now_ms().unwrap();
    b.engine
        .execute(
            f.owner.clone(),
            request(
                f,
                CallCommand::SetPolicy {
                    change: CallPolicyChange::Locked(true),
                },
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        b.repository
            .record_join_credential(
                f.call.clone(),
                f.member.principal().clone(),
                0,
                now + 60_000,
                now
            )
            .await,
        Err(CallError::Conflict {
            current_revision: 1
        })
    );
    let first = b
        .repository
        .claim_effects(now, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let reclaimed = b
        .repository
        .claim_effects(now + 30_000, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(first.id, reclaimed.id);
    assert_eq!(reclaimed.claim_generation, first.claim_generation + 1);
    assert!(
        b.repository
            .prepare_claim(first.clone(), first.effect.clone(), now + 30_000)
            .await
            .is_err()
    );
    assert_eq!(
        b.repository
            .finish_effect(first, Ok(()), now + 30_000)
            .await,
        Err(CallError::StorageUnavailable)
    );
    b.repository
        .finish_effect(reclaimed, Ok(()), now + 30_000)
        .await
        .unwrap();
}

#[tokio::test]
async fn concurrent_revision_writers_have_one_winner() {
    let b = backend(supported());
    let f = &b.fixture;
    let mut first = request(
        f,
        CallCommand::SetPolicy {
            change: CallPolicyChange::Locked(true),
        },
    );
    first.expected_revision = Some(0);
    let mut second = request(
        f,
        CallCommand::SetPolicy {
            change: CallPolicyChange::AllowLockedRejoin(false),
        },
    );
    second.expected_revision = Some(0);
    let (first, second) = tokio::join!(
        f.management.execute(f.owner.clone(), first),
        f.management.execute(f.owner.clone(), second)
    );
    assert!(matches!(
        (&first, &second),
        (
            Ok(_),
            Err(CallError::Conflict {
                current_revision: 1
            })
        ) | (
            Err(CallError::Conflict {
                current_revision: 1
            }),
            Ok(_)
        )
    ));
    let store = b.repository.0.lock().unwrap();
    assert_eq!(store.call.revision, 1);
    assert_eq!(store.audit.len(), 1);
}
