use serde::{Deserialize, Serialize};

use super::*;

pub const CALL_PROTOCOL_VERSION: u16 = 1;
pub const MAX_CALL_COMMAND_BYTES: usize = 16 * 1024;
pub const MAX_CALL_REASON_BYTES: usize = 1024;

/// Bounded typed payload carried by the host's version-negotiated MTP frame.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallWireCommand {
    pub version: u16,
    pub request: CallCommandRequest,
}

impl CallCommandRequest {
    pub fn validate(&self) -> Result<(), CallError> {
        if self.operation_id.is_nil() || self.call.id.is_nil() {
            return Err(CallError::InvalidRequest);
        }
        let target = match &self.command {
            CallCommand::Invite { target }
            | CallCommand::RevokeInvite { target }
            | CallCommand::Kick { target, .. }
            | CallCommand::Ban { target, .. }
            | CallCommand::Unban { target }
            | CallCommand::Timeout { target, .. }
            | CallCommand::ClearTimeout { target }
            | CallCommand::MuteMicrophoneNow { target }
            | CallCommand::SetMemberRestriction { target, .. }
            | CallCommand::SetRole { target, .. }
            | CallCommand::SetMemberOverride { target, .. }
            | CallCommand::SetMemberApproval { target, .. }
            | CallCommand::TransferOwnership { target } => Some(target),
            _ => None,
        };
        if target.is_some_and(|p| p.user_id == 0) {
            return Err(CallError::InvalidTarget);
        }
        match &self.command {
            CallCommand::Kick {
                reason: Some(reason),
                ..
            }
            | CallCommand::Ban {
                reason: Some(reason),
                ..
            } if reason.len() > MAX_CALL_REASON_BYTES => Err(CallError::InvalidRequest),
            CallCommand::Timeout { until_ms, .. } if *until_ms < 0 => {
                Err(CallError::InvalidRequest)
            }
            _ => Ok(()),
        }
    }
}

pub fn decode_call_command(bytes: &[u8]) -> Result<CallCommandRequest, CallError> {
    if bytes.len() > MAX_CALL_COMMAND_BYTES {
        return Err(CallError::InvalidRequest);
    }
    // Serde's struct visitors reject duplicate fields as well as unknown fields.
    let wire: CallWireCommand =
        serde_json::from_slice(bytes).map_err(|_| CallError::InvalidRequest)?;
    if wire.version != CALL_PROTOCOL_VERSION {
        return Err(CallError::UnsupportedVersion);
    }
    wire.request.validate()?;
    Ok(wire.request)
}

pub fn encode_call_command(request: &CallCommandRequest) -> Result<Vec<u8>, CallError> {
    request.validate()?;
    let bytes = serde_json::to_vec(&CallWireCommand {
        version: CALL_PROTOCOL_VERSION,
        request: request.clone(),
    })
    .map_err(|_| CallError::InvalidRequest)?;
    if bytes.len() > MAX_CALL_COMMAND_BYTES {
        return Err(CallError::InvalidRequest);
    }
    Ok(bytes)
}
