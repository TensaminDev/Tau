use tau::calls::*;
use uuid::Uuid;

fn principal(id: u64) -> CallPrincipal {
    CallPrincipal {
        authority: CallAuthority::new(format!("omega-key:{}", "a".repeat(64))).unwrap(),
        user_id: id,
    }
}

fn actor(id: u64) -> AuthenticatedCallActor {
    AuthenticatedCallActor::from_verified_session(principal(id)).unwrap()
}

fn call() -> Call {
    Call {
        id: CallId {
            owner_authority: principal(1).authority,
            id: Uuid::new_v4(),
        },
        owner: principal(1),
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
            max_members: 10,
            max_invites: 10,
            invite_ttl_ms: 60_000,
            empty_grace_ms: 30_000,
        },
        members: (1..=4)
            .map(|id| CallMember {
                principal: principal(id),
                role: match id {
                    1 => CallRole::Owner,
                    2 | 3 => CallRole::Moderator,
                    _ => CallRole::Member,
                },
                authorized: true,
                approved: true,
                guest: false,
                restrictions: Restrictions::default(),
                timeout_until_ms: None,
                overrides: PermissionOverrides::default(),
            })
            .collect(),
        invitations: vec![],
        bans: vec![],
        key_epoch: 0,
        rotation_required: false,
        rotation_generation: 0,
        key_available_generation: 0,
        key_installations: vec![],
    }
}

fn request(call: &Call, command: CallCommand) -> CallCommandRequest {
    CallCommandRequest {
        call: call.id.clone(),
        operation_id: Uuid::new_v4(),
        expected_revision: Some(call.revision),
        command,
    }
}

fn apply(call: &Call, id: u64, command: CallCommand) -> Result<CallTransition, CallError> {
    transition(call, &actor(id), &request(call, command), 1000)
}

#[test]
fn hierarchy_and_actor_are_authoritative() {
    let call = call();
    for target in 1..=3 {
        assert_eq!(
            apply(
                &call,
                2,
                CallCommand::Kick {
                    target: principal(target),
                    reason: None
                }
            ),
            Err(CallError::NotAuthorized)
        );
    }
    assert_eq!(
        apply(
            &call,
            4,
            CallCommand::Kick {
                target: principal(2),
                reason: None
            }
        ),
        Err(CallError::NotAuthorized)
    );
    assert!(
        apply(
            &call,
            2,
            CallCommand::Kick {
                target: principal(4),
                reason: None
            }
        )
        .is_ok()
    );
    assert_eq!(apply(&call, 99, CallCommand::End), Err(CallError::NotFound));
    let mut foreign = principal(1);
    foreign.authority = CallAuthority::new(format!("omega-key:{}", "b".repeat(64))).unwrap();
    assert_eq!(
        transition(
            &call,
            &AuthenticatedCallActor::from_verified_session(foreign).unwrap(),
            &request(&call, CallCommand::End),
            1000
        ),
        Err(CallError::NotFound)
    );
}

#[test]
fn undeafen_preserves_independent_microphone_restriction() {
    let mut call = call();
    for (restriction, enabled) in [
        (MemberRestriction::Microphone, true),
        (MemberRestriction::ServerDeafened, true),
    ] {
        call = apply(
            &call,
            2,
            CallCommand::SetMemberRestriction {
                target: principal(4),
                restriction,
                enabled,
            },
        )
        .unwrap()
        .call;
    }
    let effective = permissions(&call, &principal(4), 1000);
    assert!(!effective.receive_media);
    assert!(!effective.publish_microphone);
    assert!(effective.publish_camera);
    call = apply(
        &call,
        2,
        CallCommand::SetMemberRestriction {
            target: principal(4),
            restriction: MemberRestriction::ServerDeafened,
            enabled: false,
        },
    )
    .unwrap()
    .call;
    let effective = permissions(&call, &principal(4), 1000);
    assert!(effective.receive_media);
    assert!(!effective.publish_microphone);
}

#[test]
fn source_policy_is_complete_and_one_time_mute_is_not_durable() {
    let call = call();
    let muted = apply(
        &call,
        2,
        CallCommand::MuteMicrophoneNow {
            target: principal(4),
        },
    )
    .unwrap();
    assert_eq!(muted.call.members, call.members);
    assert!(muted.effects.contains(&CallEffect::MuteMicrophoneNow {
        principal: principal(4)
    }));
    let changed = apply(
        &call,
        2,
        CallCommand::SetMemberRestriction {
            target: principal(4),
            restriction: MemberRestriction::ScreenShare,
            enabled: true,
        },
    )
    .unwrap()
    .call;
    let effective = permissions(&changed, &principal(4), 1000);
    assert!(!effective.publish_screen_share);
    assert!(!effective.publish_screen_share_audio);
    assert!(effective.publish_microphone);
    assert_eq!(
        apply(
            &call,
            2,
            CallCommand::SetMemberRestriction {
                target: principal(4),
                restriction: MemberRestriction::Soundboard,
                enabled: true
            }
        ),
        Err(CallError::UnsupportedMediaCapability)
    );
}

#[test]
fn ban_survives_removal_and_unban_does_not_restore_membership() {
    let call = apply(
        &call(),
        2,
        CallCommand::Ban {
            target: principal(4),
            reason: Some("private".into()),
        },
    )
    .unwrap();
    assert!(call.call.rotation_required);
    assert_eq!(call.call.rotation_generation, 1);
    assert!(call.effects.contains(&CallEffect::RevokeEnvelopes {
        principal: principal(4)
    }));
    let call = call.call;
    assert_eq!(
        apply(
            &call,
            1,
            CallCommand::Invite {
                target: principal(4)
            }
        ),
        Err(CallError::Banned)
    );
    let call = apply(
        &call,
        2,
        CallCommand::Unban {
            target: principal(4),
        },
    )
    .unwrap()
    .call;
    assert!(!call.member(&principal(4)).unwrap().authorized);
    assert!(!permissions(&call, &principal(4), 1000).join);
    assert_eq!(call.snapshot(&actor(4), 1000), Err(CallError::NotFound));
}

#[test]
fn timeout_uses_host_clock_at_exact_boundary() {
    let call = apply(
        &call(),
        2,
        CallCommand::Timeout {
            target: principal(4),
            until_ms: 2000,
        },
    )
    .unwrap()
    .call;
    assert!(!permissions(&call, &principal(4), 1999).join);
    assert!(permissions(&call, &principal(4), 2000).join);
    assert_eq!(
        apply(&call, 4, CallCommand::Leave),
        Err(CallError::TimedOut { until_ms: 2000 })
    );
}

#[test]
fn ownership_changes_atomically_and_leaving_does_not_elect_a_successor() {
    let call = call();
    assert_eq!(
        apply(
            &call,
            2,
            CallCommand::TransferOwnership {
                target: principal(4)
            }
        ),
        Err(CallError::NotAuthorized)
    );
    let transferred = apply(
        &call,
        1,
        CallCommand::TransferOwnership {
            target: principal(4),
        },
    )
    .unwrap()
    .call;
    assert_eq!(transferred.owner, principal(4));
    assert_eq!(
        transferred.member(&principal(1)).unwrap().role,
        CallRole::Moderator
    );
    assert_eq!(
        transferred.member(&principal(4)).unwrap().role,
        CallRole::Owner
    );
    let left = apply(&call, 1, CallCommand::Leave).unwrap().call;
    assert_eq!(left.owner, principal(1));
    assert_eq!(left.member(&principal(1)).unwrap().role, CallRole::Owner);
    assert!(!left.member(&principal(1)).unwrap().authorized);
}

#[test]
fn ended_calls_cannot_be_mutated_or_joined() {
    let ended = apply(&call(), 1, CallCommand::End).unwrap().call;
    assert_eq!(ended.lifecycle, CallLifecycle::Ending);
    assert!(!permissions(&ended, &principal(1), 1000).join);
    assert_eq!(
        apply(&ended, 1, CallCommand::End),
        Err(CallError::AlreadyEnded)
    );
    assert_eq!(
        apply(
            &ended,
            1,
            CallCommand::SetPolicy {
                change: CallPolicyChange::Locked(false)
            }
        ),
        Err(CallError::AlreadyEnded)
    );
}

#[test]
fn policy_reconciles_every_member_and_snapshots_do_not_leak_reasons() {
    let call = call();
    let changed = apply(
        &call,
        1,
        CallCommand::SetPolicy {
            change: CallPolicyChange::Speak(RolePolicy::Moderators),
        },
    )
    .unwrap();
    assert_eq!(
        changed
            .effects
            .iter()
            .filter(|e| matches!(e, CallEffect::ReconcileMember { .. }))
            .count(),
        4
    );
    assert!(!permissions(&changed.call, &principal(4), 1000).publish_microphone);
    assert!(permissions(&changed.call, &principal(2), 1000).publish_microphone);
    let removed = apply(
        &call,
        2,
        CallCommand::Ban {
            target: principal(4),
            reason: Some("private reason".into()),
        },
    )
    .unwrap();
    let snapshot = serde_json::to_string(&removed.call.snapshot(&actor(1), 1000).unwrap()).unwrap();
    assert!(!snapshot.contains("private reason"));
    for effect in removed.effects {
        if let CallEffect::Publish { event } = effect {
            assert!(
                !serde_json::to_string(&event)
                    .unwrap()
                    .contains("private reason")
            );
            if event.kind != CallEventKind::Removed {
                assert!(!event.audience.contains(&principal(4)));
            }
        }
    }
}

#[test]
fn invites_require_delivery_and_lock_blocks_acceptance() {
    let call = apply(
        &call(),
        1,
        CallCommand::Invite {
            target: principal(5),
        },
    )
    .unwrap()
    .call;
    assert_eq!(
        apply(&call, 5, CallCommand::AcceptInvite),
        Err(CallError::KeyEpochPending)
    );
    let mut ready = call;
    ready.invitations[0].delivery_ready = true;
    ready.policy.locked = true;
    assert_eq!(
        apply(&ready, 5, CallCommand::AcceptInvite),
        Err(CallError::CallLocked)
    );
    ready.policy.locked = false;
    let joined = apply(&ready, 5, CallCommand::AcceptInvite).unwrap().call;
    assert!(permissions(&joined, &principal(5), 1000).join);
}

#[test]
fn codec_rejects_duplicates_unknown_variants_bounds_and_wrong_versions() {
    let request = request(
        &call(),
        CallCommand::Timeout {
            target: principal(4),
            until_ms: 100_000,
        },
    );
    let bytes = encode_call_command(&request).unwrap();
    assert_eq!(decode_call_command(&bytes).unwrap(), request);
    let text = String::from_utf8(bytes).unwrap();
    for invalid in [
        text.replacen("\"version\":1", "\"version\":1,\"version\":1", 1),
        text.replace("\"timeout\"", "\"remote_unmute\""),
        text.replacen("\"version\":1", "\"version\":1,\"actor\":1", 1),
        text.replace("100000", "-1"),
    ] {
        assert_eq!(
            decode_call_command(invalid.as_bytes()),
            Err(CallError::InvalidRequest)
        );
    }
    assert_eq!(
        decode_call_command(text.replace("\"version\":1", "\"version\":2").as_bytes()),
        Err(CallError::UnsupportedVersion)
    );
    assert_eq!(
        decode_call_command(&vec![b' '; MAX_CALL_COMMAND_BYTES + 1]),
        Err(CallError::InvalidRequest)
    );
    assert!(CallAuthority::new("omikron:1".into()).is_err());
    assert!(CallAuthority::new(format!("omega-key:{}", "A".repeat(64))).is_err());
    let reason = request_for_long_reason();
    assert_eq!(encode_call_command(&reason), Err(CallError::InvalidRequest));
}

fn request_for_long_reason() -> CallCommandRequest {
    request(
        &call(),
        CallCommand::Kick {
            target: principal(4),
            reason: Some("a".repeat(MAX_CALL_REASON_BYTES + 1)),
        },
    )
}

#[test]
fn revisions_and_decisions_are_deterministic() {
    let call = call();
    let mut request = request(&call, CallCommand::End);
    let first = transition(&call, &actor(1), &request, 1000).unwrap();
    assert_eq!(first, transition(&call, &actor(1), &request, 1000).unwrap());
    assert_eq!(first.call.revision, 1);
    request.expected_revision = Some(100);
    assert_eq!(
        transition(&call, &actor(1), &request, 1000),
        Err(CallError::Conflict {
            current_revision: 0
        })
    );
}

#[test]
fn overrides_never_bypass_restrictions_or_guest_limits() {
    let mut call = call();
    call.policy.speak = RolePolicy::Moderators;
    call = apply(
        &call,
        1,
        CallCommand::SetMemberOverride {
            target: principal(4),
            permission: MemberPermission::Microphone,
            allowed: Some(true),
        },
    )
    .unwrap()
    .call;
    assert!(permissions(&call, &principal(4), 1000).publish_microphone);
    call = apply(
        &call,
        2,
        CallCommand::SetMemberRestriction {
            target: principal(4),
            restriction: MemberRestriction::Microphone,
            enabled: true,
        },
    )
    .unwrap()
    .call;
    assert!(!permissions(&call, &principal(4), 1000).publish_microphone);
    let member = call
        .members
        .iter_mut()
        .find(|m| m.principal == principal(4))
        .unwrap();
    member.guest = true;
    member.restrictions.microphone = false;
    member.overrides.screen_share = Some(true);
    let effective = permissions(&call, &principal(4), 1000);
    assert!(!effective.publish_microphone);
    assert!(!effective.publish_screen_share);
    assert!(!effective.publish_screen_share_audio);
}

#[test]
fn configurable_moderator_permissions_cannot_be_self_escalated() {
    let mut call = call();
    call.policy.moderators.kick = false;
    call.policy.moderators_may_change_policy = true;
    assert_eq!(
        apply(
            &call,
            2,
            CallCommand::Kick {
                target: principal(4),
                reason: None
            }
        ),
        Err(CallError::NotAuthorized)
    );
    assert_eq!(
        apply(
            &call,
            2,
            CallCommand::SetPolicy {
                change: CallPolicyChange::ModeratorPermissions(ModeratorPermissions::default())
            }
        ),
        Err(CallError::NotAuthorized)
    );
    assert!(
        apply(
            &call,
            1,
            CallCommand::Kick {
                target: principal(4),
                reason: None
            }
        )
        .is_ok()
    );
}

#[test]
fn unapproved_members_fail_closed_and_explicit_invites_supply_approval() {
    let mut call = call();
    call.policy.join_policy = JoinPolicy::Approved;
    call.members
        .iter_mut()
        .find(|m| m.principal == principal(2))
        .unwrap()
        .approved = false;
    assert_eq!(
        permissions(&call, &principal(2), 1000),
        EffectivePermissions::default()
    );
    assert_eq!(
        apply(
            &call,
            2,
            CallCommand::Kick {
                target: principal(4),
                reason: None
            }
        ),
        Err(CallError::NotAuthorized)
    );
    let mut invited = apply(
        &call,
        1,
        CallCommand::Invite {
            target: principal(5),
        },
    )
    .unwrap()
    .call;
    invited.invitations[0].delivery_ready = true;
    let accepted = apply(&invited, 5, CallCommand::AcceptInvite).unwrap().call;
    assert!(accepted.member(&principal(5)).unwrap().approved);
    assert!(permissions(&accepted, &principal(5), 1000).join);
}

#[test]
fn absent_moderators_keep_target_hierarchy_and_invitees_receive_cancellation() {
    let call = apply(&call(), 2, CallCommand::Leave).unwrap().call;
    assert_eq!(
        apply(
            &call,
            3,
            CallCommand::Ban {
                target: principal(2),
                reason: None
            }
        ),
        Err(CallError::NotAuthorized)
    );
    let invited = apply(
        &call,
        1,
        CallCommand::Invite {
            target: principal(5),
        },
    )
    .unwrap()
    .call;
    let ended = apply(&invited, 1, CallCommand::End).unwrap();
    assert!(ended.effects.contains(&CallEffect::RevokeEnvelopes {
        principal: principal(5)
    }));
    assert!(ended.effects.iter().any(|effect|matches!(effect,CallEffect::Publish { event } if event.kind==CallEventKind::Removed && event.audience.contains(&principal(5)))));
}

#[test]
fn guest_admission_is_bound_to_trusted_capability_context_and_call() {
    let mut call = call();
    call.policy.join_policy = JoinPolicy::Guests;
    let guest = CallPrincipal {
        authority: call.id.owner_authority.clone(),
        user_id: 99,
    };
    let ordinary = AuthenticatedCallActor::from_verified_session(guest.clone()).unwrap();
    let command = request(&call, CallCommand::AcceptGuestAdmission);
    assert_eq!(
        transition(&call, &ordinary, &command, 1000),
        Err(CallError::NotFound)
    );
    let trusted = AuthenticatedCallActor::from_verified_guest_admission(
        guest,
        call.id.clone(),
        Uuid::new_v4(),
    )
    .unwrap();
    let accepted = transition(&call, &trusted, &command, 1000).unwrap().call;
    assert!(accepted.member(trusted.principal()).unwrap().guest);
    assert!(!permissions(&accepted, trusted.principal(), 1000).publish_microphone);
    let mut other = call.clone();
    other.id.id = Uuid::new_v4();
    assert_eq!(
        transition(
            &other,
            &trusted,
            &request(&other, CallCommand::AcceptGuestAdmission),
            1000
        ),
        Err(CallError::NotFound)
    );
}

#[test]
fn snapshot_visibility_never_substitutes_for_envelope_read_admission() {
    let mut call = call();
    call.members
        .iter_mut()
        .find(|m| m.principal == principal(4))
        .unwrap()
        .timeout_until_ms = Some(2000);
    assert!(call.snapshot(&actor(4), 1000).is_ok());
    assert_eq!(
        call.authorize_envelope_read(&principal(4), 0, 1000),
        Err(CallError::TimedOut { until_ms: 2000 })
    );
    call.policy.join_policy = JoinPolicy::Approved;
    let member = call
        .members
        .iter_mut()
        .find(|m| m.principal == principal(4))
        .unwrap();
    member.timeout_until_ms = None;
    member.approved = false;
    assert!(call.snapshot(&actor(4), 1000).is_ok());
    assert_eq!(
        call.authorize_envelope_read(&principal(4), 0, 1000),
        Err(CallError::NotAuthorized)
    );
    call.lifecycle = CallLifecycle::Ending;
    assert_eq!(
        call.authorize_envelope_read(&principal(1), 0, 1000),
        Err(CallError::AlreadyEnded)
    );
}

#[test]
fn withdrawing_invitation_material_advances_key_generation() {
    let invited = apply(
        &call(),
        1,
        CallCommand::Invite {
            target: principal(5),
        },
    )
    .unwrap()
    .call;
    let revoked = apply(
        &invited,
        1,
        CallCommand::RevokeInvite {
            target: principal(5),
        },
    )
    .unwrap();
    assert!(revoked.call.rotation_required);
    assert_eq!(
        revoked.call.rotation_generation,
        invited.rotation_generation + 1
    );
    assert!(
        revoked
            .effects
            .iter()
            .any(|e| matches!(e, CallEffect::RequestKeyRotation { .. }))
    );
}

#[test]
fn ownership_requires_an_eligible_account_but_not_new_admission_to_a_locked_call() {
    let mut call = call();
    call.policy.locked = true;
    call.policy.allow_locked_rejoin = false;
    assert!(
        apply(
            &call,
            1,
            CallCommand::TransferOwnership {
                target: principal(4)
            }
        )
        .is_ok()
    );
    call.members
        .iter_mut()
        .find(|m| m.principal == principal(4))
        .unwrap()
        .guest = true;
    assert_eq!(
        apply(
            &call,
            1,
            CallCommand::TransferOwnership {
                target: principal(4)
            }
        ),
        Err(CallError::InvalidTarget)
    );
    assert_eq!(
        apply(
            &call,
            1,
            CallCommand::SetRole {
                target: principal(4),
                role: CallRole::Moderator
            }
        ),
        Err(CallError::InvalidTarget)
    );
}

#[test]
fn eligible_account_members_can_coordinate_epochs_without_an_online_owner() {
    let mut call = call();
    call.members
        .iter_mut()
        .find(|m| m.principal == principal(1))
        .unwrap()
        .authorized = false;
    assert!(call.authorize_key_proposal(&actor(4), 1, 1000).is_ok());
    assert_eq!(
        call.authorize_key_proposal(&actor(99), 1, 1000),
        Err(CallError::NotAuthorized)
    );
    let snapshot = call.snapshot(&actor(4), 1000).unwrap();
    assert!(!snapshot.key_recipients.contains(&principal(1)));
    assert!(snapshot.key_recipients.contains(&principal(4)));
}

#[test]
fn epoch_installation_projection_accounts_for_time_based_recipient_changes() {
    let mut call = call();
    call.key_epoch = 1;
    call.key_installations = vec![principal(1), principal(2), principal(3)];
    call.members
        .iter_mut()
        .find(|m| m.principal == principal(4))
        .unwrap()
        .timeout_until_ms = Some(2000);
    assert!(!call.rotation_pending(1999));
    assert!(call.rotation_pending(2000));
    call.key_installations.push(principal(4));
    call.invitations.push(Invitation {
        recipient: principal(5),
        inviter: principal(1),
        expires_at_ms: 3000,
        delivery_ready: true,
    });
    assert!(!call.rotation_pending(2999));
    assert!(call.rotation_pending(3000));
}

#[test]
fn reinvitation_preserves_independent_moderation_state() {
    let mut call = apply(
        &call(),
        1,
        CallCommand::SetMemberRestriction {
            target: principal(4),
            restriction: MemberRestriction::Microphone,
            enabled: true,
        },
    )
    .unwrap()
    .call;
    call = apply(
        &call,
        1,
        CallCommand::SetMemberOverride {
            target: principal(4),
            permission: MemberPermission::PublishData,
            allowed: Some(false),
        },
    )
    .unwrap()
    .call;
    call = apply(&call, 4, CallCommand::Leave).unwrap().call;
    call = apply(
        &call,
        2,
        CallCommand::Invite {
            target: principal(4),
        },
    )
    .unwrap()
    .call;
    call.invitations
        .iter_mut()
        .find(|i| i.recipient == principal(4))
        .unwrap()
        .delivery_ready = true;
    call = apply(&call, 4, CallCommand::AcceptInvite).unwrap().call;
    let effective = permissions(&call, &principal(4), 1000);
    assert!(!effective.publish_microphone);
    assert!(!effective.publish_data);
    call = apply(
        &call,
        1,
        CallCommand::TransferOwnership {
            target: principal(4),
        },
    )
    .unwrap()
    .call;
    call = apply(
        &call,
        4,
        CallCommand::SetMemberRestriction {
            target: principal(4),
            restriction: MemberRestriction::Microphone,
            enabled: false,
        },
    )
    .unwrap()
    .call;
    assert!(permissions(&call, &principal(4), 1000).publish_microphone);
}

#[test]
fn retained_timeout_and_withdrawn_approval_cannot_be_reset_by_an_inviter() {
    let mut call = apply(
        &call(),
        1,
        CallCommand::Timeout {
            target: principal(4),
            until_ms: 2000,
        },
    )
    .unwrap()
    .call;
    call = apply(
        &call,
        1,
        CallCommand::Kick {
            target: principal(4),
            reason: None,
        },
    )
    .unwrap()
    .call;
    call = apply(
        &call,
        2,
        CallCommand::Invite {
            target: principal(4),
        },
    )
    .unwrap()
    .call;
    call.invitations
        .iter_mut()
        .find(|i| i.recipient == principal(4))
        .unwrap()
        .delivery_ready = true;
    assert_eq!(
        apply(&call, 4, CallCommand::AcceptInvite),
        Err(CallError::TimedOut { until_ms: 2000 })
    );
    assert_eq!(
        call.authorize_envelope_read(&principal(4), 0, 1000),
        Err(CallError::TimedOut { until_ms: 2000 })
    );
    call = apply(
        &call,
        1,
        CallCommand::ClearTimeout {
            target: principal(4),
        },
    )
    .unwrap()
    .call;
    call.policy.join_policy = JoinPolicy::Approved;
    call = apply(
        &call,
        1,
        CallCommand::SetMemberApproval {
            target: principal(4),
            approved: false,
        },
    )
    .unwrap()
    .call;
    assert_eq!(
        call.authorize_envelope_read(&principal(4), 0, 1000),
        Err(CallError::NotAuthorized)
    );
    call = apply(&call, 4, CallCommand::AcceptInvite).unwrap().call;
    assert_eq!(
        permissions(&call, &principal(4), 1000),
        EffectivePermissions::default()
    );
    call = apply(
        &call,
        1,
        CallCommand::SetMemberApproval {
            target: principal(4),
            approved: true,
        },
    )
    .unwrap()
    .call;
    assert!(permissions(&call, &principal(4), 1000).join);
}

#[test]
fn acknowledging_an_old_epoch_cannot_clear_expired_recipient_rekeying() {
    let mut call = call();
    call.key_epoch = 1;
    call.key_installations = vec![principal(1), principal(2), principal(3), principal(4)];
    call.invitations.push(Invitation {
        recipient: principal(5),
        inviter: principal(1),
        expires_at_ms: 999,
        delivery_ready: true,
    });
    let expired = apply(
        &call,
        1,
        CallCommand::AcknowledgeKeyEpoch {
            epoch: 1,
            generation: 0,
        },
    )
    .unwrap()
    .call;
    assert!(expired.rotation_required);
    assert_eq!(expired.rotation_generation, 1);
    assert!(expired.key_installations.is_empty());
    assert_eq!(
        apply(
            &expired,
            1,
            CallCommand::AcknowledgeKeyEpoch {
                epoch: 1,
                generation: 1
            }
        ),
        Err(CallError::KeyEpochPending)
    );
}
