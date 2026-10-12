use crate::{
    Admission, AdmissionError, ApplicationAuthentication, ConnectionId, LifecycleState,
    TransportAuthentication,
};

/// A trusted verifier's successful result. This is not a cryptographic proof.
/// Construct only after checking the challenge, key, identity and connection binding.
/// Consuming this value prevents reusing it across session transitions.
pub struct VerifiedApplicationAuthentication<Identity> {
    connection_id: ConnectionId,
    identity: Identity,
}

impl<Identity> VerifiedApplicationAuthentication<Identity> {
    /// Assert that the caller's verifier authenticated this identity for this connection.
    /// Tau performs no cryptographic verification. Prefer `Session::verify_application`
    /// to bind a verifier's result to the context it actually received.
    /// Reserved for trusted adapters that already perform verification outside Tau.
    pub fn assert_verified(connection_id: ConnectionId, identity: Identity) -> Self {
        Self {
            connection_id,
            identity,
        }
    }
}

/// Terminal application outcome, independent of the verified principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionOutcome {
    Closed,
    Rejected,
}

/// State for one logical connection, without transport ownership or a reconnect registry.
pub struct Session<Role, Identity> {
    id: ConnectionId,
    role: Role,
    transport: TransportAuthentication,
    authentication: ApplicationAuthentication<Identity>,
    lifecycle: LifecycleState,
    outcome: Option<SessionOutcome>,
}

impl<Role, Identity> Session<Role, Identity> {
    pub(crate) fn from_admission(
        admission: Admission<Role>,
        resolve: impl FnOnce(
            &Role,
            u64,
            &mtp::crypto::PublicKeyBundle,
        ) -> Result<Identity, AdmissionError>,
    ) -> Result<Self, AdmissionError> {
        let authentication = match &admission.transport {
            TransportAuthentication::Guest { .. } => ApplicationAuthentication::Guest,
            TransportAuthentication::TransportAuthenticated {
                mtp_client_id,
                public_key,
            } => ApplicationAuthentication::TransportAuthenticated {
                identity: resolve(&admission.role, *mtp_client_id, public_key)?,
            },
        };
        Ok(Self {
            id: admission.id,
            role: admission.role,
            transport: admission.transport,
            authentication,
            lifecycle: LifecycleState::Admitted,
            outcome: None,
        })
    }

    pub fn connection_id(&self) -> ConnectionId {
        self.id
    }
    /// Immutable admission role, not the currently running application handler.
    pub fn role(&self) -> &Role {
        &self.role
    }
    pub fn transport(&self) -> &TransportAuthentication {
        &self.transport
    }
    pub fn authentication(&self) -> &ApplicationAuthentication<Identity> {
        &self.authentication
    }
    pub fn lifecycle(&self) -> LifecycleState {
        self.lifecycle
    }

    pub fn outcome(&self) -> Option<SessionOutcome> {
        self.outcome
    }

    /// Run the application's trusted verifier with this connection context and request.
    /// The verifier may perform asynchronous I/O and returns an identity or its own error.
    /// Failure does not mutate the session. Success is an assertion by the application,
    /// bound here to this connection, and still requires a validated transition.
    /// This is the primary application-authentication path. After verification,
    /// perform attachment or admission checks, then consume the result with
    /// `authenticate_application`. Verification alone does not commit authentication.
    pub async fn verify_application<'a, Request, Error, Verification>(
        &'a self,
        request: Request,
        verify: impl FnOnce(&'a Self, Request) -> Verification,
    ) -> Result<VerifiedApplicationAuthentication<Identity>, Error>
    where
        Verification: std::future::Future<Output = Result<Identity, Error>>,
    {
        let identity = verify(self, request).await?;
        Ok(VerifiedApplicationAuthentication::assert_verified(
            self.id, identity,
        ))
    }

    pub fn authenticate_application(
        &mut self,
        verified: VerifiedApplicationAuthentication<Identity>,
    ) -> Result<(), AdmissionError> {
        if self.lifecycle == LifecycleState::Closed
            || !matches!(self.authentication, ApplicationAuthentication::Guest)
        {
            return Err(AdmissionError::InvalidAuthenticationTransition);
        }
        if verified.connection_id != self.id {
            return Err(AdmissionError::ConnectionMismatch);
        }
        self.authentication = ApplicationAuthentication::ApplicationAuthenticated {
            identity: verified.identity,
        };
        Ok(())
    }

    /// Call after the application's additional activation checks succeed.
    pub fn establish_transport_session(&mut self) -> Result<(), AdmissionError> {
        if self.lifecycle == LifecycleState::Closed
            || !matches!(
                self.authentication,
                ApplicationAuthentication::TransportAuthenticated { .. }
            )
        {
            return Err(AdmissionError::InvalidAuthenticationTransition);
        }
        let ApplicationAuthentication::TransportAuthenticated { identity } =
            std::mem::replace(&mut self.authentication, ApplicationAuthentication::Guest)
        else {
            unreachable!()
        };
        self.authentication = ApplicationAuthentication::ApplicationSessionEstablished { identity };
        Ok(())
    }

    pub fn activate(&mut self) -> Result<(), AdmissionError> {
        if self.outcome == Some(SessionOutcome::Rejected) {
            return Err(AdmissionError::RejectedActivation);
        }
        if self.lifecycle != LifecycleState::Admitted {
            return Err(AdmissionError::InvalidLifecycleTransition);
        }
        self.lifecycle = LifecycleState::Active;
        Ok(())
    }

    pub fn reject(&mut self) {
        if self.lifecycle != LifecycleState::Closed {
            self.outcome = Some(SessionOutcome::Rejected);
            self.lifecycle = LifecycleState::Closed;
        }
    }

    pub fn close(&mut self) {
        if self.lifecycle != LifecycleState::Closed {
            self.outcome = Some(SessionOutcome::Closed);
        }
        self.lifecycle = LifecycleState::Closed;
    }
}
