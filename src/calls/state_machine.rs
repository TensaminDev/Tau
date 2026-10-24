use super::*;

/// Pure decision function. The host supplies time and commits the returned
/// aggregate, audit, events, and effects together under a revision check.
pub fn transition(
    current: &Call,
    actor: &AuthenticatedCallActor,
    request: &CallCommandRequest,
    now_ms: i64,
) -> Result<CallTransition, CallError> {
    current.validate()?;
    request.validate()?;
    if current.id != request.call || now_ms < 0 {
        return Err(CallError::NotFound);
    }
    let principal = actor.principal();
    let invited = current
        .invitations
        .iter()
        .any(|i| &i.recipient == principal && i.expires_at_ms > now_ms);
    let caller = current.member(principal).filter(|m| m.authorized);
    let guest_admission = actor
        .guest_admission()
        .filter(|proof| proof.call == current.id);
    if caller.is_none() && !invited && guest_admission.is_none() {
        return Err(CallError::NotFound);
    }
    if current.terminal() {
        return Err(CallError::AlreadyEnded);
    }
    if current.lifecycle != CallLifecycle::Active {
        return Err(CallError::NotAuthorized);
    }
    if current.banned(principal) {
        return Err(CallError::Banned);
    }
    if let Some(until_ms) = current
        .member(principal)
        .and_then(|m| m.timeout_until_ms)
        .filter(|until| *until > now_ms)
    {
        return Err(CallError::TimedOut { until_ms });
    }
    if current.policy.join_policy == JoinPolicy::Approved
        && caller.is_some_and(|m| !m.approved)
        && !matches!(request.command, CallCommand::Leave)
    {
        return Err(CallError::NotAuthorized);
    }
    if request
        .expected_revision
        .is_some_and(|r| r != current.revision)
    {
        return Err(CallError::Conflict {
            current_revision: current.revision,
        });
    }
    if !matches!(
        request.command,
        CallCommand::AcceptInvite | CallCommand::AcceptGuestAdmission | CallCommand::Leave
    ) && caller.is_none()
    {
        return Err(CallError::NotAuthorized);
    }
    let role = caller.map(|m| m.role).unwrap_or(CallRole::Member);
    if role == CallRole::Moderator {
        let permitted = match &request.command {
            CallCommand::Kick { .. } => current.policy.moderators.kick,
            CallCommand::Ban { .. } | CallCommand::Unban { .. } => current.policy.moderators.ban,
            CallCommand::Timeout { .. } | CallCommand::ClearTimeout { .. } => {
                current.policy.moderators.timeouts
            }
            CallCommand::SetMemberRestriction { .. } => current.policy.moderators.restrictions,
            CallCommand::MuteMicrophoneNow { .. } | CallCommand::MuteAllMicrophonesNow { .. } => {
                current.policy.moderators.mute_now
            }
            CallCommand::SetMemberOverride { .. } => current.policy.moderators.overrides,
            CallCommand::SetMemberApproval { .. } => current.policy.moderators.approval,
            _ => true,
        };
        if !permitted {
            return Err(CallError::NotAuthorized);
        }
    }
    let moderate = |target: &CallPrincipal| -> Result<(), CallError> {
        let member = current
            .member(target)
            .filter(|m| m.authorized)
            .ok_or(CallError::InvalidTarget)?;
        if target == principal || !may_moderate(role, member.role) {
            return Err(CallError::NotAuthorized);
        }
        Ok(())
    };
    let administrative = |target: &CallPrincipal| -> Result<(), CallError> {
        let member = current.member(target).ok_or(CallError::InvalidTarget)?;
        if role == CallRole::Owner && target == principal {
            return Ok(());
        }
        if target == principal || !may_moderate(role, member.role) {
            return Err(CallError::NotAuthorized);
        }
        Ok(())
    };
    let mut call = current.clone();
    call.rotation_required = current.rotation_pending(now_ms);
    call.invitations.retain(|i| i.expires_at_ms > now_ms);
    let expired: Vec<_> = current
        .invitations
        .iter()
        .filter(|i| i.expires_at_ms <= now_ms)
        .map(|i| i.recipient.clone())
        .collect();
    let mut effects: Vec<_> = expired
        .iter()
        .map(|principal| CallEffect::RevokeEnvelopes {
            principal: principal.clone(),
        })
        .collect();
    let mut removed = expired;
    let mut rotate = !removed.is_empty();
    match &request.command {
        CallCommand::Invite { target } => {
            if call.policy.locked {
                return Err(CallError::CallLocked);
            }
            if !permissions(current, principal, now_ms).invite {
                return Err(CallError::NotAuthorized);
            }
            if call.banned(target) {
                return Err(CallError::Banned);
            }
            if target == principal || call.member(target).is_some_and(|m| m.authorized) {
                return Err(CallError::InvalidTarget);
            }
            if !call.invitations.iter().any(|i| &i.recipient == target) {
                if call.invitations.len() >= call.policy.max_invites {
                    return Err(CallError::CallFull);
                }
                call.invitations.push(Invitation {
                    recipient: target.clone(),
                    inviter: principal.clone(),
                    expires_at_ms: now_ms
                        .checked_add(call.policy.invite_ttl_ms)
                        .ok_or(CallError::InvalidRequest)?,
                    delivery_ready: false,
                });
                effects.push(CallEffect::StageInvitation {
                    principal: target.clone(),
                    epoch: call.key_epoch,
                });
            }
        }
        CallCommand::RevokeInvite { target } => {
            let invite = call
                .invitations
                .iter()
                .find(|i| &i.recipient == target)
                .ok_or(CallError::InvalidTarget)?;
            if &invite.inviter != principal
                && (role == CallRole::Member
                    || (role == CallRole::Moderator && !call.policy.moderators.revoke_invitations))
            {
                return Err(CallError::NotAuthorized);
            }
            // Even a pending invite may have received staged ciphertext before
            // its acknowledgement was lost. Recipient removal requires rekeying.
            rotate = true;
            call.invitations.retain(|i| &i.recipient != target);
            effects.push(CallEffect::RevokeEnvelopes {
                principal: target.clone(),
            });
            removed.push(target.clone());
        }
        CallCommand::AcceptInvite => {
            if call.policy.locked {
                return Err(CallError::CallLocked);
            }
            if call.member(principal).is_some_and(|m| m.authorized) {
                return Err(CallError::InvalidRequest);
            }
            if call.members.iter().filter(|m| m.authorized).count() >= call.policy.max_members {
                return Err(CallError::CallFull);
            }
            let invite = call
                .invitations
                .iter()
                .find(|i| &i.recipient == principal)
                .ok_or(CallError::InviteExpired)?;
            if !invite.delivery_ready {
                return Err(CallError::KeyEpochPending);
            }
            let previous = call.member(principal).cloned();
            let mut restrictions = previous
                .as_ref()
                .map(|m| m.restrictions.clone())
                .unwrap_or_default();
            restrictions.microphone |= call.policy.new_members_muted;
            call.invitations.retain(|i| &i.recipient != principal);
            // Keep the owner role if an absent owner accepts an explicit invite.
            call.members.retain(|m| &m.principal != principal);
            call.members.push(CallMember {
                principal: principal.clone(),
                role: if *principal == call.owner {
                    CallRole::Owner
                } else {
                    CallRole::Member
                },
                // An invitation from a permitted inviter is explicit approval.
                authorized: true,
                approved: previous.as_ref().is_none_or(|m| m.approved),
                guest: previous.as_ref().is_some_and(|m| m.guest),
                restrictions,
                overrides: previous
                    .as_ref()
                    .map(|m| m.overrides.clone())
                    .unwrap_or_default(),
                timeout_until_ms: previous.and_then(|m| m.timeout_until_ms),
            });
            effects.push(CallEffect::ReconcileMember {
                principal: principal.clone(),
            });
        }
        CallCommand::AcceptGuestAdmission => {
            if guest_admission.is_none() || call.policy.join_policy != JoinPolicy::Guests {
                return Err(CallError::NotAuthorized);
            }
            if call.policy.locked {
                return Err(CallError::CallLocked);
            }
            if call.member(principal).is_some() {
                return Err(CallError::InvalidTarget);
            }
            if call.members.iter().filter(|m| m.authorized).count() >= call.policy.max_members {
                return Err(CallError::CallFull);
            }
            call.members.push(CallMember {
                principal: principal.clone(),
                role: CallRole::Member,
                authorized: true,
                approved: true,
                guest: true,
                restrictions: Restrictions {
                    microphone: call.policy.new_members_muted,
                    ..Restrictions::default()
                },
                overrides: PermissionOverrides::default(),
                timeout_until_ms: None,
            });
            effects.push(CallEffect::ReconcileMember {
                principal: principal.clone(),
            });
        }
        CallCommand::AcknowledgeKeyEpoch { epoch, generation } => {
            if call.key_epoch != *epoch
                || call.rotation_generation != *generation
                || call.key_available_generation != *generation
            {
                return Err(CallError::KeyEpochPending);
            }
            if !call.key_installations.contains(principal) {
                call.key_installations.push(principal.clone());
            }
            let installed = call
                .members
                .iter()
                .filter(|m| call.is_admitted(&m.principal, now_ms))
                .all(|m| call.key_installations.contains(&m.principal));
            if installed {
                call.rotation_required = false;
            }
        }
        CallCommand::Leave => {
            if let Some(member) = call.members.iter_mut().find(|m| &m.principal == principal) {
                member.authorized = false;
            }
            call.invitations.retain(|i| &i.recipient != principal);
            effects.push(CallEffect::RemoveMember {
                principal: principal.clone(),
            });
            effects.push(CallEffect::RevokeEnvelopes {
                principal: principal.clone(),
            });
            removed.push(principal.clone());
            rotate = true;
        }
        CallCommand::Kick { target, .. } | CallCommand::Ban { target, .. } => {
            // Banning an already removed principal still requires moderation.
            if matches!(request.command, CallCommand::Ban { .. })
                && !current.member(target).is_some_and(|m| m.authorized)
            {
                let target_role = current
                    .member(target)
                    .map(|m| m.role)
                    .unwrap_or(CallRole::Member);
                if !may_moderate(role, target_role) || target == &call.owner || target == principal
                {
                    return Err(CallError::NotAuthorized);
                }
            } else {
                moderate(target)?;
            }
            if let Some(member) = call.members.iter_mut().find(|m| &m.principal == target) {
                member.authorized = false;
            }
            call.invitations.retain(|i| &i.recipient != target);
            if let CallCommand::Ban { reason, .. } = &request.command {
                call.bans.retain(|b| &b.principal != target);
                call.bans.push(CallBan {
                    principal: target.clone(),
                    issued_by: principal.clone(),
                    issued_at_ms: now_ms,
                    reason: reason.clone(),
                });
            }
            effects.push(CallEffect::RemoveMember {
                principal: target.clone(),
            });
            effects.push(CallEffect::RevokeEnvelopes {
                principal: target.clone(),
            });
            removed.push(target.clone());
            rotate = true;
        }
        CallCommand::Unban { target } => {
            if role == CallRole::Member {
                return Err(CallError::NotAuthorized);
            }
            if current.member(target).is_some() {
                administrative(target)?;
            }
            call.bans.retain(|b| &b.principal != target);
        }
        CallCommand::Timeout { target, until_ms } => {
            moderate(target)?;
            if *until_ms <= now_ms {
                return Err(CallError::InvalidRequest);
            }
            call.members
                .iter_mut()
                .find(|m| &m.principal == target)
                .ok_or(CallError::InvalidTarget)?
                .timeout_until_ms = Some(*until_ms);
            effects.push(CallEffect::RemoveMember {
                principal: target.clone(),
            });
        }
        CallCommand::ClearTimeout { target } => {
            administrative(target)?;
            call.members
                .iter_mut()
                .find(|m| &m.principal == target)
                .ok_or(CallError::InvalidTarget)?
                .timeout_until_ms = None;
            effects.push(CallEffect::ReconcileMember {
                principal: target.clone(),
            });
        }
        CallCommand::MuteMicrophoneNow { target } => {
            moderate(target)?;
            effects.push(CallEffect::MuteMicrophoneNow {
                principal: target.clone(),
            });
        }
        CallCommand::SetMemberRestriction {
            target,
            restriction,
            enabled,
        } => {
            administrative(target)?;
            let r = &mut call
                .members
                .iter_mut()
                .find(|m| &m.principal == target)
                .ok_or(CallError::InvalidTarget)?
                .restrictions;
            match restriction {
                MemberRestriction::Microphone => r.microphone = *enabled,
                MemberRestriction::ServerDeafened => r.server_deafened = *enabled,
                MemberRestriction::Camera => r.camera = *enabled,
                MemberRestriction::ScreenShare => r.screen_share = *enabled,
                MemberRestriction::Soundboard => return Err(CallError::UnsupportedMediaCapability),
            }
            effects.push(CallEffect::ReconcileMember {
                principal: target.clone(),
            });
        }
        CallCommand::SetPolicy { change } => {
            if role != CallRole::Owner
                && !(role == CallRole::Moderator && current.policy.moderators_may_change_policy)
            {
                return Err(CallError::NotAuthorized);
            }
            if role != CallRole::Owner
                && matches!(
                    change,
                    CallPolicyChange::ModeratorsMayEnd(_)
                        | CallPolicyChange::ModeratorsMayChangePolicy(_)
                        | CallPolicyChange::ModeratorPermissions(_)
                )
            {
                return Err(CallError::NotAuthorized);
            }
            change.apply(&mut call.policy);
            if current.members.iter().any(|m| {
                current.is_admitted(&m.principal, now_ms) != call.is_admitted(&m.principal, now_ms)
            }) {
                rotate = true;
            }
            effects.extend(call.members.iter().filter(|m| m.authorized).map(|m| {
                CallEffect::ReconcileMember {
                    principal: m.principal.clone(),
                }
            }));
        }
        CallCommand::SetMemberOverride {
            target,
            permission,
            allowed,
        } => {
            administrative(target)?;
            let overrides = &mut call
                .members
                .iter_mut()
                .find(|m| &m.principal == target)
                .ok_or(CallError::InvalidTarget)?
                .overrides;
            match permission {
                MemberPermission::Microphone => overrides.microphone = *allowed,
                MemberPermission::Camera => overrides.camera = *allowed,
                MemberPermission::ScreenShare => overrides.screen_share = *allowed,
                MemberPermission::ReceiveMedia => overrides.receive_media = *allowed,
                MemberPermission::PublishData => overrides.publish_data = *allowed,
                MemberPermission::Invite => overrides.invite = *allowed,
            }
            effects.push(CallEffect::ReconcileMember {
                principal: target.clone(),
            });
        }
        CallCommand::SetMemberApproval { target, approved } => {
            administrative(target)?;
            if target == principal && !approved {
                return Err(CallError::InvalidTarget);
            }
            let member = call
                .members
                .iter_mut()
                .find(|m| &m.principal == target)
                .ok_or(CallError::InvalidTarget)?;
            if member.approved != *approved && call.policy.join_policy == JoinPolicy::Approved {
                rotate = true;
            }
            member.approved = *approved;
            if !approved && call.policy.join_policy == JoinPolicy::Approved {
                effects.push(CallEffect::RemoveMember {
                    principal: target.clone(),
                });
                rotate = true;
            } else {
                effects.push(CallEffect::ReconcileMember {
                    principal: target.clone(),
                });
            }
        }
        CallCommand::SetRole { target, role: next } => {
            if role != CallRole::Owner || *next == CallRole::Owner {
                return Err(CallError::NotAuthorized);
            }
            moderate(target)?;
            if *next != CallRole::Member && call.member(target).is_some_and(|member| member.guest) {
                return Err(CallError::InvalidTarget);
            }
            call.members
                .iter_mut()
                .find(|m| &m.principal == target)
                .ok_or(CallError::InvalidTarget)?
                .role = *next;
            effects.push(CallEffect::ReconcileMember {
                principal: target.clone(),
            });
        }
        CallCommand::TransferOwnership { target } => {
            if role != CallRole::Owner {
                return Err(CallError::NotAuthorized);
            }
            moderate(target)?;
            if !call.is_admitted(target, now_ms)
                || call.member(target).is_some_and(|member| member.guest)
            {
                return Err(CallError::InvalidTarget);
            }
            call.owner = target.clone();
            for member in &mut call.members {
                if &member.principal == principal {
                    member.role = CallRole::Moderator;
                }
                if &member.principal == target {
                    member.role = CallRole::Owner;
                }
            }
            effects.push(CallEffect::ReconcileMember {
                principal: principal.clone(),
            });
            effects.push(CallEffect::ReconcileMember {
                principal: target.clone(),
            });
        }
        CallCommand::MuteAllMicrophonesNow { exclude_moderators } => {
            if role == CallRole::Member {
                return Err(CallError::NotAuthorized);
            }
            effects.extend(
                call.members
                    .iter()
                    .filter(|m| {
                        m.authorized
                            && (!exclude_moderators || m.role == CallRole::Member)
                            && (m.principal == *principal || may_moderate(role, m.role))
                    })
                    .map(|m| CallEffect::MuteMicrophoneNow {
                        principal: m.principal.clone(),
                    }),
            );
        }
        CallCommand::End => {
            if role != CallRole::Owner
                && !(role == CallRole::Moderator && call.policy.moderators_may_end)
            {
                return Err(CallError::NotAuthorized);
            }
            call.lifecycle = CallLifecycle::Ending;
            removed.extend(call.invitations.iter().map(|i| i.recipient.clone()));
            effects.extend(
                call.invitations
                    .iter()
                    .map(|i| CallEffect::RevokeEnvelopes {
                        principal: i.recipient.clone(),
                    }),
            );
            call.invitations.clear();
            effects.push(CallEffect::EndRoom);
            effects.push(CallEffect::RevokeLinks);
            effects.extend(call.members.iter().map(|m| CallEffect::RevokeEnvelopes {
                principal: m.principal.clone(),
            }));
        }
    }
    call.rotation_required = call.rotation_pending(now_ms);
    call.revision = call
        .revision
        .checked_add(1)
        .ok_or(CallError::InvalidRequest)?;
    effects.push(CallEffect::ProjectMetadata);
    if rotate {
        call.rotation_required = true;
        call.rotation_generation = call
            .rotation_generation
            .checked_add(1)
            .ok_or(CallError::InvalidRequest)?;
        call.key_installations.clear();
        effects.push(CallEffect::RequestKeyRotation {
            generation: call.rotation_generation,
        });
    } else if call.rotation_required && !current.rotation_required {
        effects.push(CallEffect::RequestKeyRotation {
            generation: call.rotation_generation,
        });
    }
    let audience = call
        .members
        .iter()
        .filter(|m| m.authorized && !call.banned(&m.principal))
        .map(|m| m.principal.clone())
        .collect();
    effects.push(CallEffect::Publish {
        event: CallEvent {
            version: CALL_PROTOCOL_VERSION,
            call: call.id.clone(),
            revision: call.revision,
            operation_id: request.operation_id,
            audience,
            kind: if call.terminal() {
                CallEventKind::Ending
            } else if rotate || (call.rotation_required && !current.rotation_required) {
                CallEventKind::KeyRotationRequired
            } else {
                CallEventKind::StateChanged
            },
        },
    });
    if !removed.is_empty() {
        effects.push(CallEffect::Publish {
            event: CallEvent {
                version: CALL_PROTOCOL_VERSION,
                call: call.id.clone(),
                revision: call.revision,
                operation_id: request.operation_id,
                audience: removed,
                kind: CallEventKind::Removed,
            },
        });
    }
    call.validate()?;
    Ok(CallTransition {
        call,
        effects,
        audit_command: request.command.clone(),
        actor: principal.clone(),
        operation_id: request.operation_id,
        created_at_ms: now_ms,
    })
}
