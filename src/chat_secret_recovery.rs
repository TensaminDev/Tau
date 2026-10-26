//! Versioned peer control, never a user relay or a replacement key proposal.
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use serde::{Deserialize, Serialize};

// JSON byte vectors have overhead; this also accommodates a post-quantum signed
// relay and its independently verifiable provenance without unbounded replies.
pub const MAX_RECOVERY_BYTES: usize = 2 * 1024 * 1024;
pub const RECOVERY_VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub authority: String,
    pub user_id: u64,
}

impl Principal {
    pub fn validate(&self) -> Result<(), RecoveryError> {
        if self.authority.is_empty() || self.authority.len() > 256 || self.user_id == 0 {
            return Err(RecoveryError::Unauthorized);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationPair {
    pub first: Principal,
    pub second: Principal,
}

impl ConversationPair {
    pub fn new(a: Principal, b: Principal) -> Result<Self, RecoveryError> {
        let pair = if a < b {
            Self {
                first: a,
                second: b,
            }
        } else {
            Self {
                first: b,
                second: a,
            }
        };
        pair.validate()?;
        Ok(pair)
    }

    pub fn validate(&self) -> Result<(), RecoveryError> {
        self.first.validate()?;
        self.second.validate()?;
        if self.first >= self.second {
            return Err(RecoveryError::Unauthorized);
        }
        Ok(())
    }

    pub fn partner(&self, owner: &Principal) -> Result<&Principal, RecoveryError> {
        if owner == &self.first {
            Ok(&self.second)
        } else if owner == &self.second {
            Ok(&self.first)
        } else {
            Err(RecoveryError::Unauthorized)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRequest {
    pub version: u16,
    pub pair: ConversationPair,
    pub owner: Principal,
    /// None asks for the latest committed epoch. Individual replies contain one epoch.
    pub epoch: Option<i64>,
    pub nonce: [u8; 32],
    /// Initialization probe, never permission to serve a pending envelope.
    #[serde(default)]
    pub proposal_digest: Option<[u8; 32]>,
}

impl RecoveryRequest {
    pub fn validate(&self) -> Result<(), RecoveryError> {
        self.pair.validate()?;
        self.pair.partner(&self.owner)?;
        if self.version != RECOVERY_VERSION
            || self.epoch.is_some_and(|epoch| epoch <= 0)
            || self.nonce == [0; 32]
        {
            return Err(RecoveryError::Unauthorized);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationFormat {
    TauSignedRelayV1,
    NativeMtpSealedRelayV1,
}

/// Exact bytes from a committed, cryptographically verified operation.
/// The receiver must independently verify operation and digest before restoration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveredEnvelope {
    pub epoch: i64,
    pub original_chat_id: String,
    pub original_secret_id: String,
    pub namespace: String,
    pub operation_format: OperationFormat,
    pub operation_digest: String,
    pub original_operation: Vec<u8>,
    pub original_type_map_version: String,
    pub recipient_envelope: Vec<u8>,
    pub provenance: Vec<u8>,
}

impl RecoveredEnvelope {
    pub fn validate(&self) -> Result<(), RecoveryError> {
        if self.epoch <= 0
            || self.original_chat_id.is_empty()
            || self.original_secret_id.is_empty()
            || self.original_chat_id.len() > 1024
            || self.original_secret_id.len() > 1024
            || self.namespace.is_empty()
            || self.namespace.len() > 2048
            || self.original_type_map_version.len() > 11
            || mtp::type_map::Version::parse(&self.original_type_map_version).is_none()
            || self.operation_digest.len() != 64
            || !self.operation_digest.bytes().all(|b| b.is_ascii_hexdigit())
            || self.original_operation.is_empty()
            || self.recipient_envelope.is_empty()
            || self.original_operation.len() + self.recipient_envelope.len() + self.provenance.len()
                > MAX_RECOVERY_BYTES / 4
        {
            return Err(RecoveryError::Conflict);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryError {
    #[error("no_such_conversation")]
    NoSuchConversation,
    #[error("accepted_but_envelope_unavailable")]
    AcceptedButEnvelopeUnavailable,
    #[error("unauthorized")]
    Unauthorized,
    #[error("conflict")]
    Conflict,
    #[error("retryable_peer_unavailable")]
    RetryablePeerUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryReply {
    pub request: RecoveryRequest,
    pub result: Result<RecoveredEnvelope, RecoveryError>,
}

pub fn request_frame(request: &RecoveryRequest) -> Result<CommunicationValue, RecoveryError> {
    request.validate()?;
    encode(CommunicationType::ChatSecretRecoveryRequest, request)
}

pub fn decode_request(frame: &CommunicationValue) -> Result<RecoveryRequest, RecoveryError> {
    if !frame.is_type(CommunicationType::ChatSecretRecoveryRequest) {
        return Err(RecoveryError::Unauthorized);
    }
    let request: RecoveryRequest = decode(frame)?;
    request.validate()?;
    Ok(request)
}

pub fn reply_frame(
    request: &CommunicationValue,
    reply: &RecoveryReply,
) -> Result<CommunicationValue, RecoveryError> {
    reply.request.validate()?;
    if let Ok(envelope) = &reply.result {
        envelope.validate()?;
    }
    let kind = if reply.result.is_ok() {
        CommunicationType::ChatSecretRecoveryResponse
    } else {
        CommunicationType::ChatSecretRecoveryUnavailable
    };
    Ok(encode(kind, reply)?.with_id(request.id().ok_or(RecoveryError::Unauthorized)?))
}

pub fn decode_reply(
    frame: &CommunicationValue,
    request: &RecoveryRequest,
) -> Result<RecoveryReply, RecoveryError> {
    let success = frame.is_type(CommunicationType::ChatSecretRecoveryResponse);
    if !success && !frame.is_type(CommunicationType::ChatSecretRecoveryUnavailable) {
        return Err(RecoveryError::Unauthorized);
    }
    let reply: RecoveryReply = decode(frame)?;
    if &reply.request != request || reply.result.is_ok() != success {
        return Err(RecoveryError::Conflict);
    }
    if let Ok(envelope) = &reply.result {
        envelope.validate()?;
        if request.epoch.is_some_and(|epoch| epoch != envelope.epoch) {
            return Err(RecoveryError::Conflict);
        }
    }
    Ok(reply)
}

fn encode(
    kind: CommunicationType,
    value: &impl Serialize,
) -> Result<CommunicationValue, RecoveryError> {
    let bytes = serde_json::to_vec(value).map_err(|_| RecoveryError::Conflict)?;
    if bytes.len() > MAX_RECOVERY_BYTES {
        return Err(RecoveryError::Conflict);
    }
    Ok(CommunicationValue::new(kind).add_typed_default(DataType::Json, DataValue::Bytes(bytes)))
}

fn decode<T: serde::de::DeserializeOwned>(frame: &CommunicationValue) -> Result<T, RecoveryError> {
    let field = frame
        .get_data(DataType::Json)
        .ok_or(RecoveryError::Conflict)?;
    let bytes = field.as_bytes_slice().ok_or(RecoveryError::Conflict)?;
    if bytes.len() > MAX_RECOVERY_BYTES {
        return Err(RecoveryError::Conflict);
    }
    serde_json::from_slice(bytes).map_err(|_| RecoveryError::Conflict)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> RecoveryRequest {
        let owner = Principal {
            authority: "iota:a".into(),
            user_id: 1,
        };
        RecoveryRequest {
            version: 1,
            pair: ConversationPair::new(
                owner.clone(),
                Principal {
                    authority: "iota:b".into(),
                    user_id: 1,
                },
            )
            .unwrap(),
            owner,
            epoch: Some(1),
            nonce: [1; 32],
            proposal_digest: None,
        }
    }
    #[test]
    fn canonical_pair_preserves_cross_authority_numeric_ids() {
        let r = request();
        assert_ne!(r.pair.first, r.pair.second);
        assert_eq!(decode_request(&request_frame(&r).unwrap()).unwrap(), r);
        let mut reversed = r;
        std::mem::swap(&mut reversed.pair.first, &mut reversed.pair.second);
        assert_eq!(reversed.validate(), Err(RecoveryError::Unauthorized));
    }
    #[test]
    fn replies_bind_nonce_and_outcome_type() {
        let request = request();
        let frame = request_frame(&request).unwrap();
        let reply = RecoveryReply {
            request: request.clone(),
            result: Err(RecoveryError::AcceptedButEnvelopeUnavailable),
        };
        let frame = reply_frame(&frame, &reply).unwrap();
        assert_eq!(decode_reply(&frame, &request).unwrap(), reply);
        let mut other = request;
        other.nonce = [2; 32];
        assert_eq!(decode_reply(&frame, &other), Err(RecoveryError::Conflict));
    }
    #[test]
    fn malformed_requests_and_oversized_replies_fail_closed() {
        let mut r = request();
        r.nonce = [0; 32];
        assert!(request_frame(&r).is_err());
        let frame = CommunicationValue::new(CommunicationType::ChatSecretRecoveryResponse)
            .add_typed_default(
                DataType::Json,
                DataValue::Bytes(vec![b' '; MAX_RECOVERY_BYTES + 1]),
            );
        assert!(decode_reply(&frame, &request()).is_err());
    }

    #[test]
    fn recovery_extension_keeps_legacy_wire_ids_unchanged() {
        let map = mtp::type_map::TypeMap::new(mtp::type_map::Version::new(1, 0));
        for (kind, id) in [
            (CommunicationType::SetChatSecret, 131),
            (CommunicationType::GetChatSecret, 132),
            (CommunicationType::ChatSecretResponse, 133),
            (CommunicationType::PasswordEnrollmentStart, 208),
            (CommunicationType::CallKeyEpochChanged, 237),
        ] {
            assert_eq!(map.comm_id_enum(kind), Some(id));
        }
        assert_eq!(
            map.comm_id_enum(CommunicationType::ChatSecretRecoveryRequest),
            Some(238)
        );
    }
}
