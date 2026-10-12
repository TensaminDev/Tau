use crate::AuthenticationRequirement;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AdmissionError {
    #[error("missing role description")]
    MissingDescription,
    #[error("unsupported role description: {0}")]
    UnsupportedRole(String),
    #[error("duplicate role description: {0}")]
    DuplicateRole(String),
    #[error("transport authentication does not satisfy {0:?}")]
    AuthenticationMismatch(AuthenticationRequirement),
    #[error("transport authentication is pending")]
    PendingAuthentication,
    #[error("transport authentication failed")]
    FailedAuthentication,
    #[error("authenticated transport has no verified key")]
    MissingVerifiedKey,
    #[error("guest transport carries a verified key")]
    InconsistentGuestIdentity,
    #[error("invalid application authentication transition")]
    InvalidAuthenticationTransition,
    #[error("authentication result belongs to another connection")]
    ConnectionMismatch,
    #[error("session activation rejected")]
    RejectedActivation,
    #[error("invalid lifecycle transition")]
    InvalidLifecycleTransition,
}
