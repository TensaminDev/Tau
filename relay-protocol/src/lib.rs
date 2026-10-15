//! Transport-neutral Relay V2. Identity resolution and durable replay handling belong to callers.

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

pub const SIGNING_DOMAIN: &[u8] = b"tensamin-federated-relay:v2";
pub const RELAY_CONTENT_SIGNATURE: ProtectionPurpose = ProtectionPurpose(0x31);
pub const RELAY_CONTENT_ENCRYPTION: ProtectionPurpose = ProtectionPurpose(0x32);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub authority: String,
    pub user_id: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayWire {
    pub version: u32,
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
    #[error("invalid Relay V2: {0}")]
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
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn into_frame(self, frame_id: u32) -> Result<CommunicationValue, Error> {
        let map = parse_map(&self.type_map_version)?;
        Ok(
            CommunicationValue::new_with_type_map(CommunicationType::Relay, &map)
                .with_id(frame_id)
                .add_typed_default(DataType::VersionNumber, DataValue::UnsignedNumber(2))
                .add_typed_default(DataType::SecurePayload, DataValue::Bytes(self.to_json()?)),
        )
    }
}

fn parse_map(version: &str) -> Result<TypeMap, Error> {
    let parsed =
        mtp::type_map::Version::parse(version).ok_or(Error::Invalid("type-map version"))?;
    let map = TypeMap::new(parsed);
    if map.version.to_string() != version || protected_type()?.try_to_id(&map).is_none() {
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

fn validate(wire: &RelayWire) -> Result<(), Error> {
    if wire.version != 2 {
        return Err(Error::Invalid("version"));
    }
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
    if wire.message_id.is_empty() || wire.message_id.len() > 256 {
        return Err(Error::Invalid("message ID"));
    }
    parse_map(&wire.type_map_version)?;
    Ok(())
}

/// The exact signed wire representation. `content` is decoded base64, never reserialized.
pub fn canonical_bytes(wire: &RelayWire, content: &[u8]) -> Result<Vec<u8>, Error> {
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
    let mut bytes = b"tensamin-relay-message:v2".to_vec();
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
    let map = application
        .type_map()
        .ok_or(Error::Invalid("application requires explicit type map"))?;
    if application.is_type(CommunicationType::Relay) {
        return Err(Error::Invalid("nested relay"));
    }
    let mut wire = RelayWire {
        version: 2,
        signer,
        recipient,
        destination,
        message_id,
        created_at,
        type_map_version: map.version.to_string(),
        content: String::new(),
        signature: String::new(),
    };
    validate(&wire)?;
    let signing = DualSigner::new(
        &keyring.sig_cl_secret_key,
        &keyring.sig_pq_secret_key,
        &keyring.sig_pq_public_key,
    )
    .map_err(mtp_error)?;
    let protected = ProtectedMessageBuilder::new(
        protected_type()?,
        DataValue::Bytes(application.to_bytes().map_err(mtp_error)?),
        wire.signer.user_id,
        wire.recipient.user_id,
        &signing,
        RELAY_CONTENT_SIGNATURE,
        RELAY_CONTENT_ENCRYPTION,
    )
    .message_id(derived_message_id(&wire.message_id))
    .created_at(created_at)
    .recipients(recipients)
    .type_map(map)
    .build()
    .map_err(mtp_error)?;
    let content = protected.to_bytes().map_err(mtp_error)?;
    wire.signature = STANDARD.encode(
        signing
            .sign(&canonical_bytes(&wire, &content)?)
            .map_err(mtp_error)?,
    );
    wire.content = STANDARD.encode(content);
    Ok(wire)
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
    let wire: RelayWire = serde_json::from_slice(wire_json)?;
    validate(&wire)?;
    if expected_recipient.is_some_and(|p| p != &wire.recipient)
        || expected_destination.is_some_and(|d| d != wire.destination)
    {
        return Err(Error::Invalid("unexpected destination or recipient"));
    }
    if signer_keys.is_empty() || signer_keys.len() > 8 {
        return Err(Error::Invalid("signer key history"));
    }
    let content = STANDARD.decode(&wire.content)?;
    let signature = STANDARD.decode(&wire.signature)?;
    let bytes = canonical_bytes(&wire, &content)?;
    let (classical, pq) = signature
        .split_at_checked(64)
        .ok_or(Error::Invalid("truncated signature"))?;
    if !signer_keys.iter().any(|k| {
        mtp::crypto::verify_ed25519(&k.sig_cl_public_key, &bytes, classical)
            .and_then(|_| mtp::crypto::verify_ml_dsa(&k.sig_pq_public_key, &bytes, pq))
            .is_ok()
    }) {
        return Err(Error::Invalid("outer dual signature"));
    }
    let protected =
        CommunicationValue::from_bytes_with(&content, &parse_map(&wire.type_map_version)?)
            .map_err(mtp_error)?;
    if !protected.is_type(protected_type()?) || protected.payload().as_encrypted().is_none() {
        return Err(Error::Invalid(
            "content must be an encrypted ProtectedMessage",
        ));
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
    let verified = verify_outer(
        wire_json,
        signer_keys,
        expected_recipient,
        expected_destination,
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
        ),
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
    let application =
        CommunicationValue::from_bytes_with(bytes, &parse_map(&wire.type_map_version)?)
            .map_err(mtp_error)?;
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
        "principal:v2:{}",
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
