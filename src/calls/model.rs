use serde::{Deserialize, Serialize};

use super::{CallError, CallId, CallPrincipal};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallRole {
    Owner,
    Moderator,
    Member,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallLifecycle {
    Reserved,
    Provisioning,
    Active,
    Ending,
    Ended,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolePolicy {
    All,
    Approved,
    Moderators,
    Owner,
    Nobody,
}

impl RolePolicy {
    pub fn allows(self, role: CallRole, approved: bool) -> bool {
        match self {
            Self::All => true,
            Self::Approved => approved || role != CallRole::Member,
            Self::Moderators => role != CallRole::Member,
            Self::Owner => role == CallRole::Owner,
            Self::Nobody => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinPolicy {
    Invited,
    Approved,
    Guests,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModeratorPermissions {
    pub restrictions: bool,
    pub mute_now: bool,
    pub kick: bool,
    pub ban: bool,
    pub timeouts: bool,
    pub revoke_invitations: bool,
    pub overrides: bool,
    pub approval: bool,
}

impl Default for ModeratorPermissions {
    fn default() -> Self {
        Self {
            restrictions: true,
            mute_now: true,
            kick: true,
            ban: true,
            timeouts: true,
            revoke_invitations: true,
            overrides: true,
            approval: true,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionOverrides {
    pub microphone: Option<bool>,
    pub camera: Option<bool>,
    pub screen_share: Option<bool>,
    pub receive_media: Option<bool>,
    pub publish_data: Option<bool>,
    pub invite: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallPolicy {
    pub locked: bool,
    /// Existing accepted members may rejoin a locked call.
    pub allow_locked_rejoin: bool,
    pub join_policy: JoinPolicy,
    pub invite: RolePolicy,
    pub speak: RolePolicy,
    pub camera: RolePolicy,
    pub screen_share: RolePolicy,
    pub publish_data: RolePolicy,
    pub new_members_muted: bool,
    pub guest_microphone: bool,
    pub guest_screen_share: bool,
    pub moderators_may_end: bool,
    pub moderators_may_change_policy: bool,
    #[serde(default)]
    pub moderators: ModeratorPermissions,
    pub max_members: usize,
    pub max_invites: usize,
    pub invite_ttl_ms: i64,
    pub empty_grace_ms: i64,
}

impl CallPolicy {
    pub fn validate(&self) -> Result<(), CallError> {
        if self.max_members == 0
            || self.max_members > 10_000
            || self.max_invites > 10_000
            || self.invite_ttl_ms <= 0
            || self.empty_grace_ms < 0
        {
            return Err(CallError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Restrictions {
    pub microphone: bool,
    /// Denies all incoming media, not only audio. Also denies microphone publishing.
    pub server_deafened: bool,
    pub camera: bool,
    pub screen_share: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallMember {
    pub principal: CallPrincipal,
    pub role: CallRole,
    pub authorized: bool,
    pub approved: bool,
    pub guest: bool,
    pub restrictions: Restrictions,
    #[serde(default)]
    pub overrides: PermissionOverrides,
    pub timeout_until_ms: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invitation {
    pub recipient: CallPrincipal,
    pub inviter: CallPrincipal,
    pub expires_at_ms: i64,
    pub delivery_ready: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallBan {
    pub principal: CallPrincipal,
    pub issued_by: CallPrincipal,
    pub issued_at_ms: i64,
    pub reason: Option<String>,
}

/// Authoritative aggregate. This is a storage format, never an unfiltered client snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Call {
    pub id: CallId,
    pub owner: CallPrincipal,
    pub lifecycle: CallLifecycle,
    pub revision: u64,
    pub policy: CallPolicy,
    pub members: Vec<CallMember>,
    pub invitations: Vec<Invitation>,
    pub bans: Vec<CallBan>,
    pub key_epoch: u64,
    pub rotation_required: bool,
    pub rotation_generation: u64,
    #[serde(default)]
    pub key_available_generation: u64,
    #[serde(default)]
    pub key_installations: Vec<CallPrincipal>,
}

impl Call {
    pub fn member(&self, principal: &CallPrincipal) -> Option<&CallMember> {
        self.members.iter().find(|m| &m.principal == principal)
    }

    pub fn banned(&self, principal: &CallPrincipal) -> bool {
        self.bans.iter().any(|b| &b.principal == principal)
    }

    pub fn terminal(&self) -> bool {
        matches!(self.lifecycle, CallLifecycle::Ending | CallLifecycle::Ended)
    }

    /// Host cleanup may finalize a terminal call only after its durable effects
    /// have completed. This never reopens admission or chooses another owner.
    pub fn finish_ending(&mut self) -> Result<bool, CallError> {
        match self.lifecycle {
            CallLifecycle::Ending => {
                self.lifecycle = CallLifecycle::Ended;
                Ok(true)
            }
            CallLifecycle::Ended => Ok(false),
            _ => Err(CallError::InvalidRequest),
        }
    }

    pub fn is_admitted(&self, principal: &CallPrincipal, now_ms: i64) -> bool {
        now_ms >= 0
            && self.lifecycle == CallLifecycle::Active
            && !self.banned(principal)
            && self.member(principal).is_some_and(|m| {
                m.authorized
                    && m.timeout_until_ms.is_none_or(|t| t <= now_ms)
                    && (self.policy.join_policy != JoinPolicy::Approved || m.approved)
            })
    }

    /// Snapshot visibility is broader than permission to receive key material.
    pub fn authorize_envelope_read(
        &self,
        principal: &CallPrincipal,
        epoch: u64,
        now_ms: i64,
    ) -> Result<(), CallError> {
        let member = self
            .member(principal)
            .filter(|m| m.authorized && !self.banned(principal));
        let invited = self.invitations.iter().any(|i| {
            &i.recipient == principal
                && i.delivery_ready
                && i.expires_at_ms > now_ms
                && !self.banned(principal)
        });
        if member.is_none() && !invited {
            return Err(CallError::NotFound);
        }
        if let Some(stored) = self.member(principal) {
            if let Some(until_ms) = stored.timeout_until_ms.filter(|until| *until > now_ms) {
                return Err(CallError::TimedOut { until_ms });
            }
            if self.policy.join_policy == JoinPolicy::Approved && !stored.approved {
                return Err(CallError::NotAuthorized);
            }
        }
        if self.lifecycle != CallLifecycle::Active {
            return Err(CallError::AlreadyEnded);
        }
        if let Some(member) = member {
            if let Some(until_ms) = member.timeout_until_ms.filter(|t| *t > now_ms) {
                return Err(CallError::TimedOut { until_ms });
            }
            if !self.is_admitted(principal, now_ms) {
                return Err(CallError::NotAuthorized);
            }
        }
        if epoch != self.key_epoch {
            return Err(CallError::KeyEpochPending);
        }
        Ok(())
    }

    pub fn key_recipients(&self, now_ms: i64) -> Vec<CallPrincipal> {
        self.members
            .iter()
            .filter(|m| self.is_admitted(&m.principal, now_ms))
            .map(|m| m.principal.clone())
            .chain(
                self.invitations
                    .iter()
                    .filter(|i| {
                        i.expires_at_ms > now_ms
                            && !self.banned(&i.recipient)
                            && self.member(&i.recipient).is_none_or(|m| {
                                m.timeout_until_ms.is_none_or(|until| until <= now_ms)
                                    && (self.policy.join_policy != JoinPolicy::Approved
                                        || m.approved)
                            })
                    })
                    .map(|i| i.recipient.clone()),
            )
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// The first eligible account proposal binds its proposer in the owner
    /// transaction. Key maintenance must not depend on an absent owner's device.
    pub fn authorize_key_proposal(
        &self,
        actor: &super::AuthenticatedCallActor,
        epoch: u64,
        now_ms: i64,
    ) -> Result<(), CallError> {
        if !self.is_admitted(actor.principal(), now_ms)
            || actor.guest_admission().is_some()
            || self
                .member(actor.principal())
                .is_some_and(|member| member.guest)
        {
            return Err(CallError::NotAuthorized);
        }
        if epoch <= self.key_epoch {
            return Err(CallError::KeyEpochPending);
        }
        Ok(())
    }

    pub fn rotation_pending(&self, now_ms: i64) -> bool {
        self.rotation_required
            || self.invitations.iter().any(|i| i.expires_at_ms <= now_ms)
            || (self.key_epoch > 0
                && (self.members.iter().any(|m| {
                    self.is_admitted(&m.principal, now_ms)
                        && !self.key_installations.contains(&m.principal)
                }) || self
                    .invitations
                    .iter()
                    .any(|i| i.expires_at_ms > now_ms && !i.delivery_ready)))
    }

    pub fn validate(&self) -> Result<(), CallError> {
        self.policy.validate()?;
        if self.id.id.is_nil()
            || self.owner.user_id == 0
            || self.members.iter().filter(|m| m.authorized).count() > self.policy.max_members
            || self.members.len() > 20_000
            || self.invitations.len() > self.policy.max_invites
        {
            return Err(CallError::InvalidRequest);
        }
        let mut members = std::collections::BTreeSet::new();
        for member in &self.members {
            if member.principal.user_id == 0
                || (member.guest && member.role != CallRole::Member)
                || !members.insert(&member.principal)
                || (member.role == CallRole::Owner) != (member.principal == self.owner)
                || member.timeout_until_ms.is_some_and(|t| t < 0)
            {
                return Err(CallError::InvalidRequest);
            }
        }
        if !members.contains(&self.owner) {
            return Err(CallError::InvalidRequest);
        }
        let mut recipients = std::collections::BTreeSet::new();
        for invite in &self.invitations {
            if invite.recipient.user_id == 0
                || invite.expires_at_ms < 0
                || !recipients.insert(&invite.recipient)
                || self.banned(&invite.recipient)
            {
                return Err(CallError::InvalidRequest);
            }
        }
        let mut bans = std::collections::BTreeSet::new();
        for ban in &self.bans {
            if ban.principal.user_id == 0
                || ban.principal == self.owner
                || !bans.insert(&ban.principal)
                || ban.issued_at_ms < 0
            {
                return Err(CallError::InvalidRequest);
            }
        }
        Ok(())
    }
}
