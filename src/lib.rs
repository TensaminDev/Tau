//! Post-handshake admission and session context. The application owns the transport.
mod admission;
mod auth;
mod connection;
mod error;
mod lifecycle;
mod role;
mod session;

pub use admission::{Admission, AdmissionEngine};
pub use auth::{ApplicationAuthentication, TransportAuthentication};
pub use connection::{ConnectionFacts, ConnectionId};
pub use error::AdmissionError;
pub use lifecycle::LifecycleState;
pub use role::{AuthenticationRequirement, RoleRule, RoleRules};
pub use session::{Session, SessionOutcome, VerifiedApplicationAuthentication};
