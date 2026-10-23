//! Transport-neutral federation relay. Identity resolution and durable replay belong to callers.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use mtp::codec::{
    CommunicationType, CommunicationValue, DataType, DataValue, ProtectedMessageBuilder,
    ProtectedOpenOptions, ProtectionPolicy, ProtectionPurpose, TypeMap,
    open_protected_with_keys_without_replay,
};
use mtp::crypto::{DualSigner, Keyring, PublicKeyBundle, SignatureScheme};
use serde::{Deserialize, Serialize};

pub const SIGNING_DOMAIN: &[u8] = b"tensamin-federated-relay\0";
pub const RELAY_CONTENT_SIGNATURE: ProtectionPurpose = ProtectionPurpose(0x31);
pub const RELAY_CONTENT_ENCRYPTION: ProtectionPurpose = ProtectionPurpose(0x32);
/// Fixed map for the encrypted ProtectedMessage, independent of the signed application map.
pub const PROTECTED_TYPE_MAP_VERSION: &str = "1.0";
/// Application map selected by MTP's default producers, including the SDK frame builder.
pub const DEFAULT_APPLICATION_TYPE_MAP_VERSION: mtp::type_map::Version =
    mtp::codec::PROTOCOL_VERSION;

mod limits;
pub use limits::RelayProtocolLimits;
use limits::{bound, decode_base64, json_bytes, preflight_json};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub authority: String,
    pub user_id: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayWire {
    pub signer: Principal,
    pub recipient: Principal,
    pub destination: String,
    pub message_id: String,
    pub created_at: u64,
    pub type_map_version: String,
    pub content: String,
    pub signature: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("relay limit exceeded for {field}: {actual} > {max}")]
    Limit {
        field: &'static str,
        actual: usize,
        max: usize,
    },
    #[error("invalid federation relay: {0}")]
    Invalid(&'static str),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("MTP: {0}")]
    Mtp(String),
}

fn mtp_error(error: impl std::fmt::Display) -> Error {
    Error::Mtp(error.to_string())
}

impl RelayWire {
    /// The sole federation envelope metadata is SecurePayload. Correlation IDs are transport-local.
    pub fn from_frame(frame: &CommunicationValue) -> Result<Self, Error> {
        if !frame.is_type(CommunicationType::Relay)
            || frame.sender().is_some()
            || frame.receiver().is_some()
        {
            return Err(Error::Invalid("not a federation relay"));
        }
        let map = frame.type_map().ok_or(Error::Invalid("missing type map"))?;
        let payload_id = DataType::SecurePayload
            .try_to_id(map)
            .ok_or(Error::Invalid("missing SecurePayload mapping"))?;
        let DataValue::Container(fields) = frame.payload() else {
            return Err(Error::Invalid("envelope must be a container"));
        };
        if fields.len() != 1 || fields[0].0 != payload_id {
            return Err(Error::Invalid("unexpected federation envelope metadata"));
        }
        let DataValue::Bytes(json) = &fields[0].1 else {
            return Err(Error::Invalid("missing signed relay"));
        };
        let wire = Self::from_json(json)?;
        if wire.type_map_version != map.version.to_string() {
            return Err(Error::Invalid("outer and signed type maps disagree"));
        }
        Ok(wire)
    }

    /// Bounded structural decoding. This does not authenticate the relay.
    pub fn from_json(json: &[u8]) -> Result<Self, Error> {
        Self::from_json_with_limits(json, &RelayProtocolLimits::default())
    }

    pub fn from_json_with_limits(json: &[u8], limits: &RelayProtocolLimits) -> Result<Self, Error> {
        preflight_json(json, limits.max_wire_bytes, limits, None)?;
        let wire: Self = serde_json::from_slice(json)?;
        wire.validate_with_limits(limits)?;
        Ok(wire)
    }

    /// Validate a constructed or serde-decoded wire without authenticating it.
    pub fn validate(&self) -> Result<(), Error> {
        self.validate_with_limits(&RelayProtocolLimits::default())
    }

    pub fn validate_with_limits(&self, limits: &RelayProtocolLimits) -> Result<(), Error> {
        validate(self, limits)?;
        validate_encoded_content(self, limits)?;
        limits::validate_base64(&self.content, "protected bytes", limits.max_protected_bytes)?;
        if limits::validate_base64(&self.signature, "signature bytes", dual_signature_len())?
            != dual_signature_len()
        {
            return Err(Error::Invalid("dual signature length"));
        }
        // RelayWire's fixed schema has two object levels and 25 JSON value/key tokens.
        bound("JSON depth", 2, limits.max_depth)?;
        bound("JSON fields", 25, limits.max_fields)?;
        limits::json_size(self, limits.max_wire_bytes)
    }

    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        self.to_json_with_limits(&RelayProtocolLimits::default())
    }

    pub fn to_json_with_limits(&self, limits: &RelayProtocolLimits) -> Result<Vec<u8>, Error> {
        self.validate_with_limits(limits)?;
        let json = json_bytes(self, limits.max_wire_bytes)?;
        preflight_json(&json, limits.max_wire_bytes, limits, None)?;
        Ok(json)
    }

    pub fn into_frame(self, frame_id: u32) -> Result<CommunicationValue, Error> {
        self.into_frame_with_limits(frame_id, &RelayProtocolLimits::default())
    }

    pub fn into_frame_with_limits(
        self,
        frame_id: u32,
        limits: &RelayProtocolLimits,
    ) -> Result<CommunicationValue, Error> {
        let json = self.to_json_with_limits(limits)?;
        let map = parse_map(&self.type_map_version)?;
        Ok(
            CommunicationValue::new_with_type_map(CommunicationType::Relay, &map)
                .with_id(frame_id)
                .add_typed_default(DataType::SecurePayload, DataValue::Bytes(json)),
        )
    }
}

fn parse_map(version: &str) -> Result<TypeMap, Error> {
    let parsed =
        mtp::type_map::Version::parse(version).ok_or(Error::Invalid("type-map version"))?;
    let map = TypeMap::new(parsed);
    if map.version.to_string() != version || CommunicationType::Relay.try_to_id(&map).is_none() {
        return Err(Error::Invalid(
            "unsupported or noncanonical type-map version",
        ));
    }
    Ok(map)
}

fn protected_type() -> Result<CommunicationType, Error> {
    CommunicationType::from_name("ProtectedMessage")
        .ok_or(Error::Invalid("type map lacks ProtectedMessage"))
}

fn protected_map() -> Result<TypeMap, Error> {
    let map = parse_map(PROTECTED_TYPE_MAP_VERSION)?;
    if protected_type()?.try_to_id(&map).is_none() {
        return Err(Error::Invalid("protected type map lacks ProtectedMessage"));
    }
    Ok(map)
}

fn validate_lengths(wire: &RelayWire, limits: &RelayProtocolLimits) -> Result<(), Error> {
    for principal in [&wire.signer, &wire.recipient] {
        bound(
            "authority bytes",
            principal.authority.len(),
            limits.max_authority_bytes,
        )?;
    }
    bound(
        "destination bytes",
        wire.destination.len(),
        limits.max_destination_bytes,
    )?;
    bound(
        "message ID bytes",
        wire.message_id.len(),
        limits.max_message_id_bytes,
    )?;
    bound(
        "type-map version bytes",
        wire.type_map_version.len(),
        limits.max_type_map_version_bytes,
    )?;
    Ok(())
}

fn validate(wire: &RelayWire, limits: &RelayProtocolLimits) -> Result<(), Error> {
    validate_lengths(wire, limits)?;
    for principal in [&wire.signer, &wire.recipient] {
        if principal.authority.trim().is_empty() {
            return Err(Error::Invalid("authority"));
        }
    }
    if wire.signer == wire.recipient {
        return Err(Error::Invalid("identical principals"));
    }
    let fingerprint = wire
        .destination
        .strip_prefix("iota:v1:")
        .ok_or(Error::Invalid("destination"))?;
    if fingerprint.len() != 64
        || !fingerprint
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Invalid("noncanonical destination"));
    }
    if wire.message_id.is_empty() {
        return Err(Error::Invalid("message ID"));
    }
    parse_map(&wire.type_map_version)?;
    Ok(())
}

/// The exact signed wire representation. `content` is decoded base64, never reserialized.
pub fn canonical_bytes(wire: &RelayWire, content: &[u8]) -> Result<Vec<u8>, Error> {
    canonical_bytes_with_limits(wire, content, &RelayProtocolLimits::default())
}

pub fn canonical_bytes_with_limits(
    wire: &RelayWire,
    content: &[u8],
    limits: &RelayProtocolLimits,
) -> Result<Vec<u8>, Error> {
    validate_lengths(wire, limits)?;
    bound("protected bytes", content.len(), limits.max_protected_bytes)?;
    let mut bytes = SIGNING_DOMAIN.to_vec();
    push(&mut bytes, wire.signer.authority.as_bytes())?;
    bytes.extend_from_slice(&wire.signer.user_id.to_be_bytes());
    push(&mut bytes, wire.recipient.authority.as_bytes())?;
    bytes.extend_from_slice(&wire.recipient.user_id.to_be_bytes());
    push(&mut bytes, wire.destination.as_bytes())?;
    push(&mut bytes, wire.message_id.as_bytes())?;
    bytes.extend_from_slice(&wire.created_at.to_be_bytes());
    push(&mut bytes, wire.type_map_version.as_bytes())?;
    push(&mut bytes, content)?;
    Ok(bytes)
}

fn push(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), Error> {
    let len = u32::try_from(value.len()).map_err(|_| Error::Invalid("oversized field"))?;
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

pub fn derived_message_id(message_id: &str) -> mtp::common::MessageId {
    let mut bytes = b"tensamin-relay-message\0".to_vec();
    bytes.extend_from_slice(message_id.as_bytes());
    let hash = mtp::crypto::sha256(&bytes);
    mtp::common::MessageId::new(u128::from_be_bytes(
        hash[..16].try_into().expect("SHA256 length"),
    ))
}

/// Supply encryption keys for the origin Iota, destination Iota and final client.
/// The caller authenticates those keys and their identity associations.
#[allow(clippy::too_many_arguments)]
pub fn sign_protected(
    signer: Principal,
    recipient: Principal,
    destination: String,
    message_id: String,
    created_at: u64,
    application: CommunicationValue,
    keyring: &Keyring,
    recipients: Vec<PublicKeyBundle>,
) -> Result<RelayWire, Error> {
    sign_protected_with_limits(
        signer,
        recipient,
        destination,
        message_id,
        created_at,
        application,
        keyring,
        recipients,
        &RelayProtocolLimits::default(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn sign_protected_with_limits(
    signer: Principal,
    recipient: Principal,
    destination: String,
    message_id: String,
    created_at: u64,
    application: CommunicationValue,
    keyring: &Keyring,
    recipients: Vec<PublicKeyBundle>,
    limits: &RelayProtocolLimits,
) -> Result<RelayWire, Error> {
    bound(
        "recipient keys",
        recipients.len(),
        limits.max_recipient_keys.min(mtp::crypto::MAX_RECIPIENTS),
    )?;
    if recipients.is_empty() {
        return Err(Error::Invalid("recipient keys"));
    }
    let map = application
        .type_map()
        .ok_or(Error::Invalid("application requires explicit type map"))?;
    if application.is_type(CommunicationType::Relay) {
        return Err(Error::Invalid("nested relay"));
    }
    let mut wire = RelayWire {
        signer,
        recipient,
        destination,
        message_id,
        created_at,
        type_map_version: map.version.to_string(),
        content: String::new(),
        signature: String::new(),
    };
    validate(&wire, limits)?;
    let application_bytes = application
        .to_bytes_with_limits(limits.encode(limits.max_application_bytes))
        .map_err(mtp_error)?;
    // Admit the application under the receive policy too, including allocation and recipient limits.
    decode_frame(
        &application_bytes,
        map,
        limits.max_application_bytes,
        limits,
    )?;
    let protected_map = protected_map()?;
    let signing = DualSigner::new(
        &keyring.sig_cl_secret_key,
        &keyring.sig_pq_secret_key,
        &keyring.sig_pq_public_key,
    )
    .map_err(mtp_error)?;
    let protected = ProtectedMessageBuilder::new(
        protected_type()?,
        DataValue::Bytes(application_bytes),
        wire.signer.user_id,
        wire.recipient.user_id,
        &signing,
        RELAY_CONTENT_SIGNATURE,
        RELAY_CONTENT_ENCRYPTION,
    )
    .message_id(derived_message_id(&wire.message_id))
    .created_at(created_at)
    .recipients(recipients)
    .type_map(&protected_map)
    .encode_limits(limits.encode(limits.max_protected_bytes))
    .protected_limits(limits.protected())
    .build()
    .map_err(mtp_error)?;
    let content = protected
        .to_bytes_with_limits(limits.encode(limits.max_protected_bytes))
        .map_err(mtp_error)?;
    decode_frame(&content, &protected_map, limits.max_protected_bytes, limits)?;
    wire.signature = STANDARD.encode(
        signing
            .sign(&canonical_bytes_with_limits(&wire, &content, limits)?)
            .map_err(mtp_error)?,
    );
    wire.content = STANDARD.encode(content);
    wire.to_json_with_limits(limits)?;
    Ok(wire)
}

fn decode_frame(
    bytes: &[u8],
    map: &TypeMap,
    max: usize,
    limits: &RelayProtocolLimits,
) -> Result<CommunicationValue, Error> {
    bound("MTP frame bytes", bytes.len(), max)?;
    CommunicationValue::try_from_bytes_with_type_map_and_limits(bytes, map, limits.decode(max))
        .map_err(mtp_error)
}

fn validate_encoded_content(wire: &RelayWire, limits: &RelayProtocolLimits) -> Result<(), Error> {
    bound(
        "protected base64 bytes",
        wire.content.len(),
        limits::base64_len(limits.max_protected_bytes),
    )?;
    let signature_len = mtp::crypto::SigAlgorithm::length(mtp::crypto::SigAlgorithm::DUAL)
        .expect("dual signature length");
    bound(
        "signature base64 bytes",
        wire.signature.len(),
        limits::base64_len(signature_len),
    )?;
    Ok(())
}

fn dual_signature_len() -> usize {
    mtp::crypto::SigAlgorithm::length(mtp::crypto::SigAlgorithm::DUAL)
        .expect("dual signature length")
}

#[derive(Clone, Debug)]
pub struct VerifiedRelay {
    pub wire: RelayWire,
    pub protected: CommunicationValue,
}

#[derive(Clone, Debug)]
pub struct OpenedRelay {
    pub wire: RelayWire,
    pub application: CommunicationValue,
}

pub fn verify_outer(
    wire_json: &[u8],
    signer_keys: &[PublicKeyBundle],
    expected_recipient: Option<&Principal>,
    expected_destination: Option<&str>,
) -> Result<VerifiedRelay, Error> {
    verify_outer_with_limits(
        wire_json,
        signer_keys,
        expected_recipient,
        expected_destination,
        &RelayProtocolLimits::default(),
    )
}

pub fn verify_outer_with_limits(
    wire_json: &[u8],
    signer_keys: &[PublicKeyBundle],
    expected_recipient: Option<&Principal>,
    expected_destination: Option<&str>,
    limits: &RelayProtocolLimits,
) -> Result<VerifiedRelay, Error> {
    bound("signer keys", signer_keys.len(), limits.max_signer_keys)?;
    let wire = RelayWire::from_json_with_limits(wire_json, limits)?;
    if expected_recipient.is_some_and(|p| p != &wire.recipient)
        || expected_destination.is_some_and(|d| d != wire.destination)
    {
        return Err(Error::Invalid("unexpected destination or recipient"));
    }
    if signer_keys.is_empty() {
        return Err(Error::Invalid("signer key history"));
    }
    validate_encoded_content(&wire, limits)?;
    let content = decode_base64(&wire.content, "protected bytes", limits.max_protected_bytes)?;
    let signature_len = mtp::crypto::SigAlgorithm::length(mtp::crypto::SigAlgorithm::DUAL)
        .expect("dual signature length");
    let signature = decode_base64(&wire.signature, "signature bytes", signature_len)?;
    if signature.len() != signature_len {
        return Err(Error::Invalid("dual signature length"));
    }
    let protected = decode_frame(
        &content,
        &protected_map()?,
        limits.max_protected_bytes,
        limits,
    )?;
    if !protected.is_type(protected_type()?) || protected.payload().as_encrypted().is_none() {
        return Err(Error::Invalid(
            "content must be an encrypted ProtectedMessage",
        ));
    }
    let bytes = canonical_bytes_with_limits(&wire, &content, limits)?;
    let (classical, pq) = signature
        .split_at_checked(
            mtp::crypto::SigAlgorithm::length(mtp::crypto::SigAlgorithm::ED25519)
                .expect("Ed25519 signature length"),
        )
        .ok_or(Error::Invalid("truncated signature"))?;
    if !signer_keys.iter().any(|k| {
        mtp::crypto::verify_ed25519(&k.sig_cl_public_key, &bytes, classical)
            .and_then(|_| mtp::crypto::verify_ml_dsa(&k.sig_pq_public_key, &bytes, pq))
            .is_ok()
    }) {
        return Err(Error::Invalid("outer dual signature"));
    }
    Ok(VerifiedRelay { wire, protected })
}

pub fn verify_and_open(
    wire_json: &[u8],
    signer_keys: &[PublicKeyBundle],
    keyring: &Keyring,
    expected_recipient: Option<&Principal>,
    expected_destination: Option<&str>,
) -> Result<OpenedRelay, Error> {
    verify_and_open_with_limits(
        wire_json,
        signer_keys,
        keyring,
        expected_recipient,
        expected_destination,
        &RelayProtocolLimits::default(),
    )
}

pub fn verify_and_open_with_limits(
    wire_json: &[u8],
    signer_keys: &[PublicKeyBundle],
    keyring: &Keyring,
    expected_recipient: Option<&Principal>,
    expected_destination: Option<&str>,
    limits: &RelayProtocolLimits,
) -> Result<OpenedRelay, Error> {
    let verified = verify_outer_with_limits(
        wire_json,
        signer_keys,
        expected_recipient,
        expected_destination,
        limits,
    )?;
    let wire = verified.wire;
    let opened = open_protected_with_keys_without_replay(
        &verified.protected,
        &[keyring],
        wire.signer.user_id,
        signer_keys,
        ProtectedOpenOptions::new(
            Some(wire.recipient.user_id),
            RELAY_CONTENT_SIGNATURE,
            RELAY_CONTENT_ENCRYPTION,
            ProtectionPolicy::dual(),
        )
        .with_limits(
            limits.decode(limits.max_protected_bytes),
            limits.protected(),
        )
        .with_encode_limits(limits.encode(limits.max_protected_bytes)),
    )
    .map_err(mtp_error)?;
    if opened.message_id() != derived_message_id(&wire.message_id)
        || opened.created_at() != wire.created_at
        || opened.final_recipient_id() != wire.recipient.user_id
        || opened.signer_id() != wire.signer.user_id
    {
        return Err(Error::Invalid("inner and outer binding"));
    }
    let DataValue::Bytes(bytes) = opened.content() else {
        return Err(Error::Invalid("application frame bytes"));
    };
    let application = decode_frame(
        bytes,
        &parse_map(&wire.type_map_version)?,
        limits.max_application_bytes,
        limits,
    )?;
    if application.is_type(CommunicationType::Relay) {
        return Err(Error::Invalid("nested relay"));
    }
    Ok(OpenedRelay { wire, application })
}

fn sorted_pair<'a>(first: &'a Principal, second: &'a Principal) -> [&'a Principal; 2] {
    if first <= second {
        [first, second]
    } else {
        [second, first]
    }
}

pub fn canonical_chat_id(first: &Principal, second: &Principal) -> String {
    format!(
        "principal:{}",
        URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&sorted_pair(first, second)).expect("principal JSON"))
    )
}

pub fn chat_secret_id(chat_id: &str) -> String {
    format!("chat:{chat_id}:main")
}

pub fn canonical_chat_participants(first: &Principal, second: &Principal) -> [String; 2] {
    sorted_pair(first, second).map(|p| serde_json::to_string(p).expect("principal JSON"))
}

pub mod bridge;
#[cfg(feature = "wasm")]
mod wasm;
