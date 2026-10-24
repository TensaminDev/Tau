//! Reusable interface checks for host implementations of [`CallManagement`].
//!
//! Each factory invocation must create an isolated active, unlocked call with
//! default moderator permissions, all source policies set to `RolePolicy::All`,
//! and four approved, authorized non-guest members with no restrictions or
//! overrides. Moderators initially cannot change policy or end the call.
//! `outsider` must have no invitation or admission. Media must support
//! source permissions, receive denial, and immediate microphone muting. Actors
//! must come from the host's verified-session boundary. No credentials or network
//! access are required by this suite. Panics identify a violated contract.
use std::{future::Future, sync::Arc};

use uuid::Uuid;

use super::*;

pub struct CallManagementFixture {
    pub management: Arc<dyn CallManagement>,
    pub call: CallId,
    pub owner: AuthenticatedCallActor,
    pub moderator: AuthenticatedCallActor,
    pub member: AuthenticatedCallActor,
    pub other_moderator: AuthenticatedCallActor,
    pub outsider: AuthenticatedCallActor,
}

impl CallManagementFixture {
    fn request(&self, command: CallCommand) -> CallCommandRequest {
        CallCommandRequest {
            call: self.call.clone(),
            operation_id: Uuid::new_v4(),
            expected_revision: None,
            command,
        }
    }

    async fn execute(
        &self,
        actor: &AuthenticatedCallActor,
        command: CallCommand,
    ) -> Result<CallCommandResult, CallError> {
        self.management
            .execute(actor.clone(), self.request(command))
            .await
    }

    async fn snapshot(&self, actor: &AuthenticatedCallActor) -> CallSnapshot {
        self.management
            .snapshot(actor.clone(), self.call.clone())
            .await
            .expect("authorized snapshot")
    }

    async fn join(&self, actor: &AuthenticatedCallActor) -> Result<JoinGrant, CallError> {
        self.management
            .authorize_join(
                actor.clone(),
                JoinRequest {
                    call: self.call.clone(),
                },
            )
            .await
    }
}

/// Run against any host adapter. The factory is called once per independent
/// scenario and may asynchronously seed its own repository and session handles.
pub async fn call_management_conformance<F, Fut>(mut factory: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<CallManagementFixture, CallError>>,
{
    let f = factory().await.expect("seed visibility fixture");
    assert_eq!(f.snapshot(&f.owner).await.owner, *f.owner.principal());
    assert_eq!(
        f.management
            .snapshot(f.outsider.clone(), f.call.clone())
            .await,
        Err(CallError::NotFound)
    );
    assert!(matches!(
        f.join(&f.outsider).await,
        Err(CallError::NotFound)
    ));
    assert_eq!(
        f.execute(&f.outsider, CallCommand::End).await,
        Err(CallError::NotFound)
    );
    let target = f.member.principal().clone();
    for actor in [&f.member, &f.moderator] {
        let target = if actor.principal() == f.member.principal() {
            f.owner.principal()
        } else {
            f.other_moderator.principal()
        };
        assert_eq!(
            f.execute(
                actor,
                CallCommand::Kick {
                    target: target.clone(),
                    reason: None
                }
            )
            .await,
            Err(CallError::NotAuthorized)
        );
    }
    assert_eq!(
        f.execute(
            &f.moderator,
            CallCommand::SetPolicy {
                change: CallPolicyChange::Locked(true)
            }
        )
        .await,
        Err(CallError::NotAuthorized)
    );
    f.execute(
        &f.owner,
        CallCommand::SetPolicy {
            change: CallPolicyChange::ModeratorsMayChangePolicy(true),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        f.execute(
            &f.moderator,
            CallCommand::SetPolicy {
                change: CallPolicyChange::ModeratorsMayEnd(true)
            }
        )
        .await,
        Err(CallError::NotAuthorized)
    );
    let permissions = ModeratorPermissions {
        kick: false,
        ..Default::default()
    };
    f.execute(
        &f.owner,
        CallCommand::SetPolicy {
            change: CallPolicyChange::ModeratorPermissions(permissions),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        f.execute(
            &f.moderator,
            CallCommand::Kick {
                target,
                reason: None
            }
        )
        .await,
        Err(CallError::NotAuthorized)
    );

    let f = factory().await.expect("seed source fixture");
    let target = f.member.principal().clone();
    assert!(
        f.join(&f.member)
            .await
            .unwrap()
            .permissions
            .publish_microphone
    );
    f.execute(
        &f.moderator,
        CallCommand::MuteMicrophoneNow {
            target: target.clone(),
        },
    )
    .await
    .unwrap();
    assert!(
        f.snapshot(&f.member).await.permissions.publish_microphone,
        "one-shot mute must not become a persistent restriction"
    );
    for (restriction, enabled) in [
        (MemberRestriction::Microphone, true),
        (MemberRestriction::ServerDeafened, true),
        (MemberRestriction::ServerDeafened, false),
    ] {
        f.execute(
            &f.moderator,
            CallCommand::SetMemberRestriction {
                target: target.clone(),
                restriction,
                enabled,
            },
        )
        .await
        .unwrap();
        let snapshot = f.snapshot(&f.member).await;
        assert!(!snapshot.permissions.publish_microphone);
        assert_eq!(
            snapshot.permissions.receive_media,
            !snapshot
                .member
                .as_ref()
                .unwrap()
                .restrictions
                .server_deafened
        );
        assert!(snapshot.permissions.publish_camera);
        assert!(snapshot.permissions.publish_screen_share);
        assert!(snapshot.permissions.publish_screen_share_audio);
        assert!(snapshot.permissions.publish_data);
    }
    f.execute(
        &f.moderator,
        CallCommand::SetMemberRestriction {
            target: target.clone(),
            restriction: MemberRestriction::Microphone,
            enabled: false,
        },
    )
    .await
    .unwrap();
    assert!(f.snapshot(&f.member).await.permissions.publish_microphone);
    f.execute(
        &f.owner,
        CallCommand::SetPolicy {
            change: CallPolicyChange::ScreenShare(RolePolicy::Nobody),
        },
    )
    .await
    .unwrap();
    let snapshot = f.snapshot(&f.member).await;
    assert!(
        !snapshot.permissions.publish_screen_share
            && !snapshot.permissions.publish_screen_share_audio
    );
    assert!(snapshot.permissions.publish_microphone && snapshot.permissions.publish_camera);
    f.execute(
        &f.owner,
        CallCommand::SetMemberOverride {
            target,
            permission: MemberPermission::ScreenShare,
            allowed: Some(true),
        },
    )
    .await
    .unwrap();
    assert!(
        f.join(&f.member)
            .await
            .unwrap()
            .permissions
            .publish_screen_share_audio
    );

    let f = factory().await.expect("seed retry fixture");
    let initial = f.snapshot(&f.owner).await.revision;
    let mut request = f.request(CallCommand::Leave);
    request.expected_revision = Some(initial);
    // Discarding the first response models a transport losing a committed reply.
    let committed = f
        .management
        .execute(f.member.clone(), request.clone())
        .await
        .unwrap();
    assert_eq!(committed.revision, initial + 1);
    assert_eq!(
        f.management
            .snapshot(f.member.clone(), f.call.clone())
            .await,
        Err(CallError::NotFound)
    );
    assert_eq!(
        f.management
            .execute(f.member.clone(), request.clone())
            .await
            .unwrap(),
        committed
    );
    request.command = CallCommand::End;
    assert_eq!(
        f.management.execute(f.member.clone(), request).await,
        Err(CallError::OperationConflict)
    );
    let mut stale = f.request(CallCommand::SetPolicy {
        change: CallPolicyChange::Locked(true),
    });
    stale.expected_revision = Some(initial);
    assert_eq!(
        f.management.execute(f.owner.clone(), stale).await,
        Err(CallError::Conflict {
            current_revision: committed.revision
        })
    );
    assert_eq!(f.snapshot(&f.owner).await.revision, committed.revision);

    let f = factory().await.expect("seed lock fixture");
    f.execute(
        &f.owner,
        CallCommand::SetPolicy {
            change: CallPolicyChange::Locked(true),
        },
    )
    .await
    .unwrap();
    f.execute(
        &f.owner,
        CallCommand::SetPolicy {
            change: CallPolicyChange::AllowLockedRejoin(false),
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        f.join(&f.member).await,
        Err(CallError::CallLocked)
    ));
    assert_eq!(
        f.execute(
            &f.owner,
            CallCommand::Invite {
                target: f.outsider.principal().clone()
            }
        )
        .await,
        Err(CallError::CallLocked)
    );
    f.execute(
        &f.owner,
        CallCommand::SetPolicy {
            change: CallPolicyChange::AllowLockedRejoin(true),
        },
    )
    .await
    .unwrap();
    assert!(f.join(&f.member).await.unwrap().permissions.join);

    let f = factory().await.expect("seed ban fixture");
    let target = f.member.principal().clone();
    f.execute(
        &f.moderator,
        CallCommand::Ban {
            target: target.clone(),
            reason: Some("conformance".into()),
        },
    )
    .await
    .unwrap();
    assert!(matches!(f.join(&f.member).await, Err(CallError::NotFound)));
    assert_eq!(
        f.execute(
            &f.owner,
            CallCommand::Invite {
                target: target.clone()
            }
        )
        .await,
        Err(CallError::Banned)
    );
    f.execute(&f.owner, CallCommand::Unban { target })
        .await
        .unwrap();
    assert!(matches!(f.join(&f.member).await, Err(CallError::NotFound)));
    assert_eq!(
        f.execute(&f.member, CallCommand::AcceptInvite).await,
        Err(CallError::NotFound)
    );

    let f = factory().await.expect("seed ownership fixture");
    f.execute(
        &f.owner,
        CallCommand::TransferOwnership {
            target: f.member.principal().clone(),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        f.snapshot(&f.member).await.member.unwrap().role,
        CallRole::Owner
    );
    assert_eq!(
        f.snapshot(&f.owner).await.member.unwrap().role,
        CallRole::Moderator
    );
    assert_eq!(
        f.execute(
            &f.owner,
            CallCommand::TransferOwnership {
                target: f.other_moderator.principal().clone()
            }
        )
        .await,
        Err(CallError::NotAuthorized)
    );
    f.execute(&f.member, CallCommand::End).await.unwrap();
    assert!(matches!(
        f.join(&f.member).await,
        Err(CallError::AlreadyEnded)
    ));
    assert_eq!(
        f.execute(
            &f.member,
            CallCommand::SetPolicy {
                change: CallPolicyChange::Locked(false)
            }
        )
        .await,
        Err(CallError::AlreadyEnded)
    );
    assert!(!f.snapshot(&f.member).await.permissions.join);
}
