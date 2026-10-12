use mtp::crypto::PublicKeyBundle;

/// MTP's verified result, retained unchanged after application authentication.
pub enum TransportAuthentication {
    Guest {
        temporary_id: u64,
    },
    TransportAuthenticated {
        mtp_client_id: u64,
        public_key: PublicKeyBundle,
    },
}

impl TransportAuthentication {
    pub fn mtp_client_id(&self) -> u64 {
        match self {
            Self::Guest { temporary_id } => *temporary_id,
            Self::TransportAuthenticated { mtp_client_id, .. } => *mtp_client_id,
        }
    }
}

/// Verified principal and its origin. Handler selection does not change this state.
#[derive(Debug, PartialEq, Eq)]
pub enum ApplicationAuthentication<Identity> {
    Guest,
    TransportAuthenticated { identity: Identity },
    ApplicationAuthenticated { identity: Identity },
    ApplicationSessionEstablished { identity: Identity },
}
