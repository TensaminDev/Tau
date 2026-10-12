use mtp::{
    codec::Version,
    crypto::PublicKeyBundle,
    host::{AuthState, MTPConnection},
};
use std::net::SocketAddr;

/// One accepted connection instance, independent of account and application session IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(uuid::Uuid);

impl ConnectionId {
    /// Read-only correlation with an application's UUID-based session registry.
    /// This identifier names a connection instance, not an authentication credential.
    pub fn as_uuid(&self) -> uuid::Uuid {
        self.0
    }

    pub(crate) fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

/// Trusted post-handshake metadata supplied by the application adapter.
/// `Authenticated` must come from MTP's successful verification, never a peer's claim.
/// Description, version, path and remote address are policy context, not identity proof.
pub struct ConnectionFacts<'a> {
    pub mtp_client_id: u64,
    pub description: Option<&'a str>,
    pub auth_state: AuthState,
    pub public_key: Option<&'a PublicKeyBundle>,
    pub version: Version,
    pub path: &'a str,
    pub remote_addr: Option<SocketAddr>,
}

impl<'a> ConnectionFacts<'a> {
    pub fn from_mtp<S, R, P>(connection: &'a MTPConnection<S, R, P>) -> Self {
        Self {
            mtp_client_id: connection.client_id,
            description: connection.description.as_deref(),
            auth_state: connection.auth_state.clone(),
            public_key: connection.client_public_key.as_ref(),
            version: connection.version.clone(),
            path: &connection.path,
            remote_addr: connection.remote_addr,
        }
    }
}
