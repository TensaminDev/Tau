use crate::{
    AdmissionError, AuthenticationRequirement, ConnectionFacts, ConnectionId, RoleRules, Session,
    TransportAuthentication,
};
use mtp::host::AuthState;

pub struct AdmissionEngine<Role> {
    rules: RoleRules<Role>,
}

pub struct Admission<Role> {
    pub(crate) id: ConnectionId,
    pub(crate) role: Role,
    pub(crate) transport: TransportAuthentication,
}

impl<Role: Clone> AdmissionEngine<Role> {
    pub fn new(rules: RoleRules<Role>) -> Self {
        Self { rules }
    }

    /// Validate trusted post-handshake MTP facts. Each call mints a distinct connection
    /// identity; the owning adapter must call once per accepted connection.
    pub fn admit(&self, facts: &ConnectionFacts<'_>) -> Result<Admission<Role>, AdmissionError> {
        let transport = match facts.auth_state {
            AuthState::Pending => return Err(AdmissionError::PendingAuthentication),
            AuthState::Failed => return Err(AdmissionError::FailedAuthentication),
            AuthState::Authenticated => TransportAuthentication::TransportAuthenticated {
                mtp_client_id: facts.mtp_client_id,
                public_key: facts
                    .public_key
                    .ok_or(AdmissionError::MissingVerifiedKey)?
                    .clone(),
            },
            AuthState::Unauthenticated => {
                if facts.public_key.is_some() {
                    return Err(AdmissionError::InconsistentGuestIdentity);
                }
                TransportAuthentication::Guest {
                    temporary_id: facts.mtp_client_id,
                }
            }
        };
        let rule = self.rules.resolve(facts.description)?;
        let required = match transport {
            TransportAuthentication::Guest { .. } => AuthenticationRequirement::Guest,
            TransportAuthentication::TransportAuthenticated { .. } => {
                AuthenticationRequirement::Authenticated
            }
        };
        if rule.authentication != required {
            return Err(AdmissionError::AuthenticationMismatch(rule.authentication));
        }
        Ok(Admission {
            id: ConnectionId::new(),
            role: rule.role.clone(),
            transport,
        })
    }
}

impl<Role> Admission<Role> {
    pub fn connection_id(&self) -> ConnectionId {
        self.id
    }
    pub fn role(&self) -> &Role {
        &self.role
    }
    pub fn transport(&self) -> &TransportAuthentication {
        &self.transport
    }

    /// Attach an identity using the application's trusted transport-to-principal policy.
    /// The resolver runs only for authenticated transport, never for a guest.
    /// MTP has verified possession of the supplied key against the application's key
    /// lookup. The adapter must bind that key and ID to the requested role's namespace,
    /// and reject inconsistent identities. Tau cannot validate arbitrary identity types.
    /// Every resolver receives the verified key, even when a centralized key lookup has
    /// already established its relationship to the application principal.
    /// Omikron can rely on Omega's role-specific key lookup. Decentralized Iota
    /// derives its canonical node identity from the complete verified public key
    /// and separately checks the trusted node directory before activation.
    /// A successful handshake establishes possession of the key accepted by MTP's
    /// configured resolver; it does not authorize application operations. This
    /// callback maps that transport result to the application's principal. Directory
    /// lookups and subsequent authority checks belong to the application.
    pub fn into_session<Identity>(
        self,
        resolve: impl FnOnce(
            &Role,
            u64,
            &mtp::crypto::PublicKeyBundle,
        ) -> Result<Identity, AdmissionError>,
    ) -> Result<Session<Role, Identity>, AdmissionError> {
        Session::from_admission(self, resolve)
    }
}
