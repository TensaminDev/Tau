use serde::{Deserialize, Serialize};

use super::{Call, CallPrincipal, CallRole};

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectivePermissions {
    pub publish_microphone: bool,
    pub publish_camera: bool,
    pub publish_screen_share: bool,
    pub publish_screen_share_audio: bool,
    pub receive_media: bool,
    pub publish_data: bool,
    pub invite: bool,
    pub moderate: bool,
    pub join: bool,
}

pub fn permissions(call: &Call, principal: &CallPrincipal, now_ms: i64) -> EffectivePermissions {
    let Some(member) = call.member(principal) else {
        return EffectivePermissions::default();
    };
    if !call.is_admitted(principal, now_ms) {
        return EffectivePermissions::default();
    }
    let policy = &call.policy;
    let allowed = |p: super::RolePolicy| p.allows(member.role, member.approved);
    let overrides = &member.overrides;
    let screen = overrides
        .screen_share
        .unwrap_or_else(|| allowed(policy.screen_share))
        && !member.restrictions.screen_share
        && (!member.guest || policy.guest_screen_share);
    EffectivePermissions {
        publish_microphone: overrides
            .microphone
            .unwrap_or_else(|| allowed(policy.speak))
            && !member.restrictions.microphone
            && !member.restrictions.server_deafened
            && (!member.guest || policy.guest_microphone),
        publish_camera: overrides.camera.unwrap_or_else(|| allowed(policy.camera))
            && !member.restrictions.camera,
        publish_screen_share: screen,
        publish_screen_share_audio: screen,
        receive_media: overrides.receive_media.unwrap_or(true)
            && !member.restrictions.server_deafened,
        publish_data: overrides
            .publish_data
            .unwrap_or_else(|| allowed(policy.publish_data)),
        invite: !policy.locked && overrides.invite.unwrap_or_else(|| allowed(policy.invite)),
        moderate: member.role != CallRole::Member,
        join: (!policy.locked || policy.allow_locked_rejoin)
            && (policy.join_policy != super::JoinPolicy::Approved || member.approved),
    }
}

pub fn may_moderate(actor: CallRole, target: CallRole) -> bool {
    matches!(
        (actor, target),
        (CallRole::Owner, CallRole::Moderator | CallRole::Member)
            | (CallRole::Moderator, CallRole::Member)
    )
}
