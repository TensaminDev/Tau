//! File protocol v1. Byte fields are ciphertext, never plaintext keys or names.
use crate::Principal;
use serde::{Deserialize, Serialize};

pub const MAX_METADATA_BYTES: usize = 16 * 1024;
pub const MAX_CONTROL_BYTES: usize = 192 * 1024;
pub const REPLICA_CHUNK_BYTES: usize = 256 * 1024;
pub const PAGE_SIZE: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileKey {
    pub origin: Principal,
    pub file_id: String,
    pub version: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyEnvelope {
    pub recipient: Principal,
    pub key_id: String,
    pub wrapping_scheme: String,
    pub kem_ciphertext: Vec<u8>,
    pub encrypted_dek: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileManifest {
    pub key: FileKey,
    pub ciphertext_sha256: Vec<u8>,
    pub ciphertext_size: i64,
    pub crypto_format: String,
    pub manifest_ciphertext: Vec<u8>,
    pub envelope: KeyEnvelope,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareOffer {
    pub manifest: FileManifest,
    pub chat_id: String,
    pub grant_revision: i64,
    pub expires_at: i64,
    pub signing_public_key: String,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareRevoke {
    pub key: FileKey,
    pub recipient: Principal,
    pub chat_id: String,
    pub grant_revision: i64,
    pub signing_public_key: String,
    pub signature: Vec<u8>,
}

impl ShareOffer {
    /// Detached user signature, independently verifiable after an Iota opens the
    /// transport seal. Integer strings avoid cross-language JSON rounding.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let m = &self.manifest;
        serde_json::to_vec(&serde_json::json!([
            "tensamin-file-share-v1",
            m.key.origin.authority,
            m.key.origin.user_id.to_string(),
            m.key.file_id,
            m.key.version.to_string(),
            m.ciphertext_sha256,
            m.ciphertext_size.to_string(),
            m.crypto_format,
            m.manifest_ciphertext,
            m.envelope.recipient.authority,
            m.envelope.recipient.user_id.to_string(),
            m.envelope.key_id,
            m.envelope.wrapping_scheme,
            m.envelope.kem_ciphertext,
            m.envelope.encrypted_dek,
            self.chat_id,
            self.grant_revision.to_string(),
            self.expires_at.to_string(),
            self.signing_public_key
        ]))
        .expect("file signature array is JSON serializable")
    }
}

impl ShareRevoke {
    pub fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!([
            "tensamin-file-revoke-v1",
            self.key.origin.authority,
            self.key.origin.user_id.to_string(),
            self.key.file_id,
            self.key.version.to_string(),
            self.recipient.authority,
            self.recipient.user_id.to_string(),
            self.chat_id,
            self.grant_revision.to_string(),
            self.signing_public_key
        ]))
        .expect("file signature array is JSON serializable")
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishVersion {
    pub manifest: FileManifest,
    pub asset_id: String,
    pub expected_predecessor: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileUploadStart {
    pub upload_id: String,
    pub asset_id: String,
    pub size: i64,
    pub sha256: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RewrapKey {
    pub key: FileKey,
    pub expected_key_id: String,
    pub envelope: KeyEnvelope,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataUpdate {
    pub key: FileKey,
    pub expected_revision: i64,
    pub manifest_ciphertext: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Folder {
    pub folder_id: String,
    pub parent_folder_id: String,
    pub encrypted_name: Vec<u8>,
    pub revision: i64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Placement {
    pub placement_id: String,
    pub origin: Principal,
    pub file_id: String,
    pub folder_id: String,
    pub hidden: bool,
    pub revision: i64,
    pub encrypted_metadata: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteEntry {
    pub id: String,
    pub expected_revision: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListPage {
    /// `private`, `chat:<canonical chat ID>`, `folders`, `versions`, or `shares`.
    pub namespace: String,
    pub folder_id: String,
    pub after: i64,
    #[serde(default)]
    pub origin: Option<Principal>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangesPage {
    pub after: i64,
    pub upper: Option<i64>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicaRead {
    pub key: FileKey,
    pub recipient: Principal,
    pub chat_id: String,
    pub grant_revision: i64,
    pub offset: i64,
}

pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl FileKey {
    pub fn validate(&self) -> Result<(), crate::Error> {
        self.origin.validate()?;
        if !valid_id(&self.file_id) || self.version <= 0 {
            return Err(crate::Error::Invalid("file key"));
        }
        Ok(())
    }
}

impl FileManifest {
    pub fn validate(&self) -> Result<(), crate::Error> {
        self.key.validate()?;
        self.envelope.recipient.validate()?;
        if self.ciphertext_sha256.len() != 32
            || self.ciphertext_size <= 0
            || self.ciphertext_size % (65536 + 24 + 16) != 0
            || self.crypto_format != "tensamin-file-chunks-v1"
            || self.manifest_ciphertext.is_empty()
            || self.manifest_ciphertext.len() > MAX_METADATA_BYTES
            || self.envelope.wrapping_scheme != "tensamin-file-dek-kem-v1"
            || !valid_id(&self.envelope.key_id)
            || self.envelope.kem_ciphertext.is_empty()
            || self.envelope.kem_ciphertext.len() > 4096
            || self.envelope.encrypted_dek.len() != 72
        {
            return Err(crate::Error::Invalid("file manifest"));
        }
        Ok(())
    }
}
