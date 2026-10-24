use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "error", rename_all = "snake_case", deny_unknown_fields)]
pub enum CallError {
    #[error("call not found")]
    NotFound,
    #[error("not authorized")]
    NotAuthorized,
    #[error("not a member")]
    NotMember,
    #[error("banned")]
    Banned,
    #[error("timed out until {until_ms}")]
    TimedOut { until_ms: i64 },
    #[error("call locked")]
    CallLocked,
    #[error("invitation expired")]
    InviteExpired,
    #[error("call full")]
    CallFull,
    #[error("call ended")]
    AlreadyEnded,
    #[error("invalid target")]
    InvalidTarget,
    #[error("invalid request")]
    InvalidRequest,
    #[error("unsupported protocol version")]
    UnsupportedVersion,
    #[error("unsupported media capability")]
    UnsupportedMediaCapability,
    #[error("revision conflict at {current_revision}")]
    Conflict { current_revision: u64 },
    #[error("operation ID reused with different content")]
    OperationConflict,
    #[error("envelope conflicts with stored ciphertext")]
    EnvelopeConflict,
    #[error("rate limited")]
    RateLimited,
    #[error("storage unavailable")]
    StorageUnavailable,
    #[error("media enforcement pending")]
    MediaEnforcementPending,
    #[error("key epoch pending")]
    KeyEpochPending,
}
