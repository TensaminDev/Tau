use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{CallId, CallPolicy, CallPrincipal, CallRole, JoinPolicy, RolePolicy};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallCommandRequest {
    pub call: CallId,
    pub operation_id: Uuid,
    pub expected_revision: Option<u64>,
    pub command: CallCommand,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum CallCommand {
    Invite {
        target: CallPrincipal,
    },
    RevokeInvite {
        target: CallPrincipal,
    },
    AcceptInvite,
    AcceptGuestAdmission,
    AcknowledgeKeyEpoch {
        epoch: u64,
        generation: u64,
    },
    Leave,
    Kick {
        target: CallPrincipal,
        reason: Option<String>,
    },
    Ban {
        target: CallPrincipal,
        reason: Option<String>,
    },
    Unban {
        target: CallPrincipal,
    },
    Timeout {
        target: CallPrincipal,
        until_ms: i64,
    },
    ClearTimeout {
        target: CallPrincipal,
    },
    MuteMicrophoneNow {
        target: CallPrincipal,
    },
    SetMemberRestriction {
        target: CallPrincipal,
        restriction: MemberRestriction,
        enabled: bool,
    },
    SetMemberOverride {
        target: CallPrincipal,
        permission: MemberPermission,
        allowed: Option<bool>,
    },
    SetMemberApproval {
        target: CallPrincipal,
        approved: bool,
    },
    SetPolicy {
        change: CallPolicyChange,
    },
    SetRole {
        target: CallPrincipal,
        role: CallRole,
    },
    TransferOwnership {
        target: CallPrincipal,
    },
    MuteAllMicrophonesNow {
        exclude_moderators: bool,
    },
    End,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberRestriction {
    Microphone,
    ServerDeafened,
    Camera,
    ScreenShare,
    Soundboard,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberPermission {
    Microphone,
    Camera,
    ScreenShare,
    ReceiveMedia,
    PublishData,
    Invite,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "policy",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CallPolicyChange {
    Locked(bool),
    AllowLockedRejoin(bool),
    Join(JoinPolicy),
    Invite(RolePolicy),
    Speak(RolePolicy),
    Camera(RolePolicy),
    ScreenShare(RolePolicy),
    PublishData(RolePolicy),
    NewMembersMuted(bool),
    GuestMicrophone(bool),
    GuestScreenShare(bool),
    ModeratorsMayEnd(bool),
    ModeratorsMayChangePolicy(bool),
    ModeratorPermissions(super::ModeratorPermissions),
}

impl CallPolicyChange {
    pub(crate) fn apply(&self, policy: &mut CallPolicy) {
        if let Self::ModeratorPermissions(v) = self {
            policy.moderators = v.clone();
            return;
        }
        match *self {
            Self::Locked(v) => policy.locked = v,
            Self::AllowLockedRejoin(v) => policy.allow_locked_rejoin = v,
            Self::Join(v) => policy.join_policy = v,
            Self::Invite(v) => policy.invite = v,
            Self::Speak(v) => policy.speak = v,
            Self::Camera(v) => policy.camera = v,
            Self::ScreenShare(v) => policy.screen_share = v,
            Self::PublishData(v) => policy.publish_data = v,
            Self::NewMembersMuted(v) => policy.new_members_muted = v,
            Self::GuestMicrophone(v) => policy.guest_microphone = v,
            Self::GuestScreenShare(v) => policy.guest_screen_share = v,
            Self::ModeratorsMayEnd(v) => policy.moderators_may_end = v,
            Self::ModeratorsMayChangePolicy(v) => policy.moderators_may_change_policy = v,
            Self::ModeratorPermissions(_) => unreachable!("handled above"),
        }
    }
}
