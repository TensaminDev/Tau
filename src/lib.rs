//! Post-handshake admission, session context, shared protocol helpers, and
//! transport-neutral call management.
//! The application owns the transport.
mod admission;
mod auth;
pub mod calls;
pub mod chat_secret_recovery;
mod connection;
mod error;
mod framing;
mod keyring;
mod lifecycle;
mod mtp_compat;
mod requests;
mod role;
mod route;
mod security;
mod session;

pub use admission::{Admission, AdmissionEngine};
pub use auth::{ApplicationAuthentication, TransportAuthentication};
pub use connection::{ConnectionFacts, ConnectionId};
pub use error::AdmissionError;
pub use framing::{
    CommunicationResponseExt, data_i64, data_string, error_response, typed_container,
};
pub use keyring::{
    MAX_PRIVATE_KEYRING_BYTES, create_private_keyring, load_private_keyring, open_private_keyring,
    read_private_keyring, replace_private_keyring, verify_private_keyring,
};
pub use lifecycle::LifecycleState;
pub use mtp_compat::{
    MtpFieldError, OptionalDataValueExt, ProtocolValueError, RequiredCommunicationFields,
    positive_data_i64,
};
pub use requests::{
    CorrelationError, PROTOCOL_ERROR_TYPES, PendingResponse, RequestError, ResponseCorrelator,
    ResponseExpectation, is_protocol_error, password_response_expectation,
};
pub use role::{AuthenticationRequirement, RoleRule, RoleRules};
pub use route::RouteTarget;
pub use security::{CHAT_SECRET_PEER_CONTROL_TYPES, MessageSecurityClass, RELAY_ONLY_TYPES, message_security_class_with};
pub use session::{Session, SessionOutcome, VerifiedApplicationAuthentication};
