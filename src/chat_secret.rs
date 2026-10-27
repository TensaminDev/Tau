//! Canonical Chat Secret reads. Transport routing IDs never select an owner.
use crate::relay_protocol::{ConversationPair, Principal, chat_secret_id};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue, TypeMap};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "i64", into = "i64")]
pub struct SecretEpoch(i64);

impl SecretEpoch {
    pub fn get(self) -> i64 {
        self.0
    }
}

impl TryFrom<i64> for SecretEpoch {
    type Error = ReadCodecError;
    fn try_from(epoch: i64) -> Result<Self, Self::Error> {
        if epoch <= 0 {
            return Err(ReadCodecError::Invalid("positive epoch required"));
        }
        Ok(Self(epoch))
    }
}

impl From<SecretEpoch> for i64 {
    fn from(epoch: SecretEpoch) -> Self {
        epoch.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadRequest {
    pub owner: Principal,
    pub pair: ConversationPair,
    pub epoch: Option<SecretEpoch>,
    pub secret_id: String,
}

/// The epoch in `scope` is the committed epoch, never a request for latest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadResponse {
    pub scope: ReadRequest,
    pub encrypted_secret: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
    pub wrapping_scheme: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl ReadResponse {
    fn validate_for(&self, request: &ReadRequest) -> Result<(), ReadCodecError> {
        self.scope.validate()?;
        if self.scope.epoch.is_none()
            || self.scope.owner != request.owner
            || self.scope.pair != request.pair
            || self.scope.secret_id != request.secret_id
            || request
                .epoch
                .is_some_and(|epoch| Some(epoch) != self.scope.epoch)
            || self.encrypted_secret.is_empty()
            || self.kem_ciphertext.is_empty()
            || self
                .encrypted_secret
                .len()
                .saturating_add(self.kem_ciphertext.len())
                > crate::chat_secret_recovery::MAX_RECOVERY_BYTES / 4
            || self.wrapping_scheme.is_empty()
            || self.wrapping_scheme.len() > 128
            || self.wrapping_scheme.trim() != self.wrapping_scheme
            || self.created_at < 0
            || self.updated_at < self.created_at
        {
            return Err(ReadCodecError::Invalid("committed owner envelope"));
        }
        Ok(())
    }

    pub fn to_frame(
        &self,
        request: &CommunicationValue,
    ) -> Result<CommunicationValue, ReadCodecError> {
        use crate::CommunicationResponseExt;
        let expected = ReadRequest::from_frame(request)?;
        self.validate_for(&expected)?;
        let map = request.type_map().ok_or(ReadCodecError::Dictionary)?;
        require_map(
            map,
            CommunicationType::ChatSecretResponse,
            &[
                DataType::EncryptedSecret,
                DataType::KemCiphertext,
                DataType::WrappingScheme,
                DataType::CreatedAt,
                DataType::UpdatedAt,
            ],
        )?;
        let mut frame =
            CommunicationValue::new_with_type_map(CommunicationType::ChatSecretResponse, map)
                .with_request_id(request)
                .with_payload(self.scope.to_frame(map, 1)?.payload().clone())
                .add_typed_default(
                    DataType::EncryptedSecret,
                    DataValue::Bytes(self.encrypted_secret.clone()),
                )
                .add_typed_default(
                    DataType::KemCiphertext,
                    DataValue::Bytes(self.kem_ciphertext.clone()),
                )
                .add_typed_default(
                    DataType::WrappingScheme,
                    DataValue::Str(self.wrapping_scheme.clone()),
                )
                .add_typed_default(
                    DataType::CreatedAt,
                    DataValue::SignedNumber(self.created_at.into()),
                )
                .add_typed_default(
                    DataType::UpdatedAt,
                    DataValue::SignedNumber(self.updated_at.into()),
                );
        if let Some(sender) = request.sender() {
            frame = frame.with_receiver(sender);
        }
        Ok(frame)
    }

    pub fn from_frame(
        frame: &CommunicationValue,
        request: &CommunicationValue,
    ) -> Result<Self, ReadCodecError> {
        if !frame.is_type(CommunicationType::ChatSecretResponse)
            || frame.id() != request.id()
            || request.sender().is_some_and(|sender| frame.receiver() != Some(sender))
            || frame.type_map() != request.type_map()
        {
            return Err(ReadCodecError::Invalid(
                "response type, correlation or dictionary",
            ));
        }
        let map = frame.type_map().ok_or(ReadCodecError::Dictionary)?;
        let fields = [
            DataType::UserId,
            DataType::ChatId,
            DataType::SecretId,
            DataType::VersionNumber,
            DataType::EncryptedSecret,
            DataType::KemCiphertext,
            DataType::WrappingScheme,
            DataType::CreatedAt,
            DataType::UpdatedAt,
        ];
        require_map(map, CommunicationType::ChatSecretResponse, &fields)?;
        let mut seen = std::collections::HashSet::new();
        let mut scope = Vec::new();
        for (kind, value) in frame.iter_typed_data() {
            let kind = kind
                .filter(|kind| fields.contains(kind))
                .ok_or(ReadCodecError::Invalid("response fields"))?;
            if !seen.insert(kind) {
                return Err(ReadCodecError::Invalid("duplicate response field"));
            }
            if fields[..4].contains(&kind) {
                scope.push((
                    kind.try_to_id(map).ok_or(ReadCodecError::Dictionary)?,
                    value.clone(),
                ));
            }
        }
        let scope = ReadRequest::from_frame(
            &CommunicationValue::new_with_type_map(CommunicationType::GetChatSecret, map)
                .with_payload(DataValue::Container(scope)),
        )?;
        let bytes = |kind| {
            frame
                .get_data(kind)
                .and_then(DataValue::as_bytes_slice)
                .filter(|bytes| bytes.len() <= crate::chat_secret_recovery::MAX_RECOVERY_BYTES / 4)
                .map(<[u8]>::to_vec)
                .ok_or(ReadCodecError::Invalid("wrapped envelope bytes"))
        };
        let timestamp = |kind| match frame.get_data(kind) {
            Some(DataValue::SignedNumber(value)) => {
                i64::try_from(*value).map_err(|_| ReadCodecError::Invalid("timestamp range"))
            }
            Some(DataValue::UnsignedNumber(value)) => {
                i64::try_from(*value).map_err(|_| ReadCodecError::Invalid("timestamp range"))
            }
            _ => Err(ReadCodecError::Invalid("timestamp")),
        };
        let response = Self {
            scope,
            encrypted_secret: bytes(DataType::EncryptedSecret)?,
            kem_ciphertext: bytes(DataType::KemCiphertext)?,
            wrapping_scheme: frame
                .get_data(DataType::WrappingScheme)
                .and_then(DataValue::as_str)
                .filter(|value| value.len() <= 128)
                .ok_or(ReadCodecError::Invalid("wrapping scheme"))?
                .into(),
            created_at: timestamp(DataType::CreatedAt)?,
            updated_at: timestamp(DataType::UpdatedAt)?,
        };
        response.validate_for(&ReadRequest::from_frame(request)?)?;
        Ok(response)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadUnavailable {
    NoSuchConversation,
    Pending,
    EpochUnavailable,
    AcceptedButEnvelopeUnavailable,
    Unauthorized,
    Conflict,
    RetryableDependency,
}

impl ReadUnavailable {
    pub fn code(self) -> &'static str {
        match self {
            Self::NoSuchConversation => "no_such_conversation",
            Self::Pending => "pending",
            Self::EpochUnavailable => "epoch_unavailable",
            Self::AcceptedButEnvelopeUnavailable => "accepted_but_envelope_unavailable",
            Self::Unauthorized => "unauthorized",
            Self::Conflict => "conflict",
            Self::RetryableDependency => "retryable_dependency",
        }
    }

    pub fn retryable(self) -> bool {
        matches!(
            self,
            Self::Pending | Self::AcceptedButEnvelopeUnavailable | Self::RetryableDependency
        )
    }

    pub fn to_frame(
        self,
        request: &CommunicationValue,
    ) -> Result<CommunicationValue, ReadCodecError> {
        let map = request.type_map().ok_or(ReadCodecError::Dictionary)?;
        let kind = match self {
            Self::NoSuchConversation | Self::EpochUnavailable => CommunicationType::ErrorNotSet,
            Self::Unauthorized => CommunicationType::ErrorNotAuthenticated,
            Self::Pending | Self::Conflict => CommunicationType::ErrorInvalidData,
            Self::AcceptedButEnvelopeUnavailable | Self::RetryableDependency => {
                CommunicationType::ErrorInternal
            }
        };
        require_map(map, kind, &[DataType::ErrorType, DataType::Json])?;
        let data =
            serde_json::to_vec(&serde_json::json!({"state": self, "retryable": self.retryable()}))
                .map_err(|_| ReadCodecError::Invalid("unavailable outcome encoding"))?;
        Ok(crate::error_response(request, kind, map)
            .add_typed_default(DataType::ErrorType, DataValue::Str(self.code().into()))
            .add_typed_default(DataType::Json, DataValue::Bytes(data)))
    }

    pub fn from_frame(
        frame: &CommunicationValue,
        request: &CommunicationValue,
    ) -> Result<Self, ReadCodecError> {
        if frame.id() != request.id()
            || request.sender().is_some_and(|sender| frame.receiver() != Some(sender))
            || frame.type_map() != request.type_map()
        {
            return Err(ReadCodecError::Invalid(
                "response correlation or dictionary",
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for (kind, _) in frame.iter_typed_data() {
            if !matches!(kind, Some(DataType::ErrorType | DataType::Json)) || !seen.insert(kind) {
                return Err(ReadCodecError::Invalid("response fields"));
            }
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Outcome {
            state: ReadUnavailable,
            retryable: bool,
        }
        let bytes = frame
            .get_data(DataType::Json)
            .and_then(DataValue::as_bytes_slice)
            .filter(|bytes| bytes.len() <= 256)
            .ok_or(ReadCodecError::Invalid("response outcome"))?;
        let outcome: Outcome = serde_json::from_slice(bytes)
            .map_err(|_| ReadCodecError::Invalid("response outcome"))?;
        if frame.get_type() != outcome.state.to_frame(request)?.get_type()
            || frame
                .get_data(DataType::ErrorType)
                .and_then(DataValue::as_str)
                != Some(outcome.state.code())
            || outcome.retryable != outcome.state.retryable()
        {
            return Err(ReadCodecError::Invalid("response state"));
        }
        Ok(outcome.state)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReadCodecError {
    #[error("missing or unsupported dictionary")]
    Dictionary,
    #[error("invalid Chat Secret read: {0}")]
    Invalid(&'static str),
}

fn require_map(
    map: &TypeMap,
    kind: CommunicationType,
    fields: &[DataType],
) -> Result<(), ReadCodecError> {
    if map.fingerprint().is_none()
        || kind.try_to_id(map).is_none()
        || fields.iter().any(|field| field.try_to_id(map).is_none())
    {
        return Err(ReadCodecError::Dictionary);
    }
    Ok(())
}

impl ReadRequest {
    pub fn validate(&self) -> Result<(), ReadCodecError> {
        self.pair
            .partner(&self.owner)
            .map_err(|_| ReadCodecError::Invalid("owner is not a participant"))?;
        let chat = self
            .pair
            .chat_id()
            .map_err(|_| ReadCodecError::Invalid("canonical pair"))?;
        if self.secret_id != chat_secret_id(&chat) {
            return Err(ReadCodecError::Invalid("secret namespace"));
        }
        Ok(())
    }

    pub fn from_frame(frame: &CommunicationValue) -> Result<Self, ReadCodecError> {
        let map = frame.type_map().ok_or(ReadCodecError::Dictionary)?;
        let fields = [
            DataType::UserId,
            DataType::ChatId,
            DataType::SecretId,
            DataType::VersionNumber,
        ];
        require_map(map, CommunicationType::GetChatSecret, &fields)?;
        if !frame.is_type(CommunicationType::GetChatSecret) {
            return Err(ReadCodecError::Invalid("request type"));
        }
        let mut seen = std::collections::HashSet::new();
        for (kind, _) in frame.iter_typed_data() {
            if !kind.is_some_and(|kind| fields.contains(&kind)) || !seen.insert(kind) {
                return Err(ReadCodecError::Invalid("duplicate or unknown field"));
            }
        }
        let string = |kind| {
            frame
                .get_data(kind)
                .and_then(DataValue::as_str)
                .filter(|value| value.len() <= 1024)
                .ok_or(ReadCodecError::Invalid("required string field"))
        };
        let owner_json = string(DataType::UserId)?;
        let owner: Principal = serde_json::from_str(owner_json)
            .map_err(|_| ReadCodecError::Invalid("owner principal"))?;
        if serde_json::to_string(&owner).map_err(|_| ReadCodecError::Invalid("owner principal"))?
            != owner_json
        {
            return Err(ReadCodecError::Invalid("noncanonical owner"));
        }
        let pair = ConversationPair::from_chat_id(string(DataType::ChatId)?)
            .map_err(|_| ReadCodecError::Invalid("conversation namespace"))?;
        let epoch = match frame.get_data(DataType::VersionNumber) {
            None => None,
            Some(DataValue::SignedNumber(value)) => Some(SecretEpoch::try_from(
                i64::try_from(*value).map_err(|_| ReadCodecError::Invalid("epoch range"))?,
            )?),
            Some(DataValue::UnsignedNumber(value)) => Some(SecretEpoch::try_from(
                i64::try_from(*value).map_err(|_| ReadCodecError::Invalid("epoch range"))?,
            )?),
            Some(_) => return Err(ReadCodecError::Invalid("integer epoch required")),
        };
        let request = Self {
            owner,
            pair,
            epoch,
            secret_id: string(DataType::SecretId)?.into(),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn to_frame(
        &self,
        map: &TypeMap,
        correlation_id: u32,
    ) -> Result<CommunicationValue, ReadCodecError> {
        self.validate()?;
        require_map(
            map,
            CommunicationType::GetChatSecret,
            &[
                DataType::UserId,
                DataType::ChatId,
                DataType::SecretId,
                DataType::VersionNumber,
            ],
        )?;
        let mut frame =
            CommunicationValue::new_with_type_map(CommunicationType::GetChatSecret, map)
                .with_id(correlation_id)
                .add_typed_default(
                    DataType::UserId,
                    DataValue::Str(
                        serde_json::to_string(&self.owner)
                            .map_err(|_| ReadCodecError::Invalid("owner encoding"))?,
                    ),
                )
                .add_typed_default(
                    DataType::ChatId,
                    DataValue::Str(
                        self.pair
                            .chat_id()
                            .map_err(|_| ReadCodecError::Invalid("pair encoding"))?,
                    ),
                )
                .add_typed_default(DataType::SecretId, DataValue::Str(self.secret_id.clone()));
        if let Some(epoch) = self.epoch {
            frame = frame.add_typed_default(
                DataType::VersionNumber,
                DataValue::SignedNumber(epoch.get().into()),
            );
        }
        Ok(frame)
    }
}
