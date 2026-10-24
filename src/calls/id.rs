use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::CallError;

/// Matches Iota's fingerprint authorities. Legacy locators are explicit,
/// normalized migration inputs, never inferred from a display hostname.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CallAuthority(String);

impl CallAuthority {
    pub fn new(value: String) -> Result<Self, CallError> {
        let fingerprint = value
            .strip_prefix("omega-key:")
            .or_else(|| value.strip_prefix("omikron-key:"))
            .or_else(|| value.strip_prefix("authority:iota:v1:"));
        let valid = if let Some(fingerprint) = fingerprint {
            fingerprint.len() == 64
                && fingerprint
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        } else if let Some(locator) = value.strip_prefix("omega:") {
            !locator.is_empty()
                && locator.len() <= 253
                && locator
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-:[]".contains(&b))
        } else {
            false
        };
        if !valid {
            return Err(CallError::InvalidRequest);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CallAuthority {
    type Error = CallError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<CallAuthority> for String {
    fn from(value: CallAuthority) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallPrincipal {
    pub authority: CallAuthority,
    pub user_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallId {
    pub owner_authority: CallAuthority,
    pub id: Uuid,
}

/// An assertion by a trusted host adapter, not a wire credential. Intentionally
/// does not implement Deserialize. A host must verify its session before use.
#[derive(Clone, Debug)]
pub struct AuthenticatedCallActor {
    principal: CallPrincipal,
    guest_admission: Option<VerifiedGuestAdmission>,
}

#[derive(Clone, Debug)]
pub struct VerifiedGuestAdmission {
    pub call: CallId,
    pub capability_id: Uuid,
}

impl AuthenticatedCallActor {
    pub fn from_verified_session(principal: CallPrincipal) -> Result<Self, CallError> {
        if principal.user_id == 0 {
            return Err(CallError::NotAuthorized);
        }
        Ok(Self {
            principal,
            guest_admission: None,
        })
    }

    /// The host verifies the opaque capability, binds it to this session, and
    /// rechecks revocation/usage limits in the membership transaction.
    pub fn from_verified_guest_admission(
        principal: CallPrincipal,
        call: CallId,
        capability_id: Uuid,
    ) -> Result<Self, CallError> {
        if principal.user_id == 0
            || principal.authority != call.owner_authority
            || capability_id.is_nil()
        {
            return Err(CallError::NotAuthorized);
        }
        Ok(Self {
            principal,
            guest_admission: Some(VerifiedGuestAdmission {
                call,
                capability_id,
            }),
        })
    }

    pub fn guest_admission(&self) -> Option<&VerifiedGuestAdmission> {
        self.guest_admission.as_ref()
    }

    pub fn principal(&self) -> &CallPrincipal {
        &self.principal
    }
}
