use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::*;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallMemberSnapshot {
    pub principal: CallPrincipal,
    pub role: CallRole,
    pub guest: bool,
    pub approved: Option<bool>,
    pub overrides: Option<PermissionOverrides>,
    pub permissions: Option<EffectivePermissions>,
    pub restrictions: Option<Restrictions>,
    pub timeout_until_ms: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallSnapshot {
    pub version: u16,
    pub call: CallId,
    pub revision: u64,
    pub lifecycle: CallLifecycle,
    pub owner: CallPrincipal,
    pub member: Option<CallMember>,
    pub members: Vec<CallMemberSnapshot>,
    pub invitations: Vec<Invitation>,
    pub key_recipients: Vec<CallPrincipal>,
    pub invitation: Option<Invitation>,
    pub policy: CallPolicy,
    pub permissions: EffectivePermissions,
    pub key_epoch: u64,
    pub rotation_required: bool,
    pub enforcement: EnforcementStatus,
    pub rotation_generation: u64,
    pub key_available_generation: u64,
    pub next_key_epoch: u64,
}

impl Call {
    pub fn snapshot(
        &self,
        actor: &AuthenticatedCallActor,
        now_ms: i64,
    ) -> Result<CallSnapshot, CallError> {
        let principal = actor.principal();
        let member = self
            .member(principal)
            .filter(|m| m.authorized && !self.banned(principal));
        let invitation = self.invitations.iter().find(|i| {
            &i.recipient == principal
                && i.delivery_ready
                && i.expires_at_ms > now_ms
                && !self.banned(principal)
        });
        if member.is_none() && invitation.is_none() {
            return Err(CallError::NotFound);
        }
        let may_moderate = permissions(self, principal, now_ms).moderate;
        Ok(CallSnapshot {
            version: CALL_PROTOCOL_VERSION,
            call: self.id.clone(),
            revision: self.revision,
            lifecycle: self.lifecycle,
            owner: self.owner.clone(),
            member: member.cloned(),
            members: self
                .members
                .iter()
                .filter(|m| m.authorized && !self.banned(&m.principal))
                .map(|m| CallMemberSnapshot {
                    principal: m.principal.clone(),
                    role: m.role,
                    guest: m.guest,
                    approved: (may_moderate || &m.principal == principal).then_some(m.approved),
                    overrides: (may_moderate || &m.principal == principal)
                        .then(|| m.overrides.clone()),
                    permissions: (may_moderate || &m.principal == principal)
                        .then(|| permissions(self, &m.principal, now_ms)),
                    restrictions: (may_moderate || &m.principal == principal)
                        .then(|| m.restrictions.clone()),
                    timeout_until_ms: if may_moderate || &m.principal == principal {
                        m.timeout_until_ms
                    } else {
                        None
                    },
                })
                .collect(),
            invitations: self
                .invitations
                .iter()
                .filter(|i| {
                    i.expires_at_ms > now_ms
                        && !self.banned(&i.recipient)
                        && (may_moderate || &i.inviter == principal || &i.recipient == principal)
                })
                .cloned()
                .collect(),
            key_recipients: if self.is_admitted(principal, now_ms)
                && member.is_some_and(|m| !m.guest)
            {
                self.key_recipients(now_ms)
            } else {
                Vec::new()
            },
            invitation: invitation.cloned(),
            policy: self.policy.clone(),
            permissions: permissions(self, principal, now_ms),
            key_epoch: self.key_epoch,
            rotation_required: self.rotation_pending(now_ms),
            enforcement: EnforcementStatus::PendingEnforcement,
            rotation_generation: self.rotation_generation,
            key_available_generation: self.key_available_generation,
            next_key_epoch: self
                .key_epoch
                .checked_add(1)
                .ok_or(CallError::KeyEpochPending)?,
        })
    }
}

/// Events contain no moderation reasons or other members' restrictions.
/// Consumers detect revision gaps and fetch a requester-scoped snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallEvent {
    pub version: u16,
    pub call: CallId,
    pub revision: u64,
    pub operation_id: Uuid,
    pub audience: Vec<CallPrincipal>,
    pub kind: CallEventKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallEventKind {
    StateChanged,
    Removed,
    KeyRotationRequired,
    KeyEpochAvailable,
    Ending,
    Ended,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "effect", rename_all = "snake_case", deny_unknown_fields)]
pub enum CallEffect {
    ProvisionRoom,
    InspectRoom,
    ProjectMetadata,
    ReconcileMember {
        principal: CallPrincipal,
    },
    RemoveMember {
        principal: CallPrincipal,
    },
    EnsureRevoked {
        principal: CallPrincipal,
        credentials_valid_until_ms: i64,
    },
    /// One-time action must be bound by the adapter to tracks present when claimed.
    MuteMicrophoneNow {
        principal: CallPrincipal,
    },
    BoundMicrophoneMute {
        principal: CallPrincipal,
        participant_sid: String,
        track_sids: Vec<String>,
    },
    StageInvitation {
        principal: CallPrincipal,
        epoch: u64,
    },
    RevokeEnvelopes {
        principal: CallPrincipal,
    },
    RevokeEnvelopesThrough {
        principal: CallPrincipal,
        max_epoch: u64,
    },
    RequestKeyRotation {
        generation: u64,
    },
    EndRoom,
    EnsureEnded {
        credentials_valid_until_ms: i64,
    },
    RevokeLinks,
    Publish {
        event: CallEvent,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementStatus {
    Applied,
    PendingEnforcement,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallCommandResult {
    pub revision: u64,
    pub status: EnforcementStatus,
    pub rotation_required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallTransition {
    pub call: Call,
    pub effects: Vec<CallEffect>,
    /// Private, immutable audit payload. Never publish this as a client event.
    pub audit_command: CallCommand,
    pub actor: CallPrincipal,
    pub operation_id: Uuid,
    pub created_at_ms: i64,
}
