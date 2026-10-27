//! Principal-qualified routing claims inside native sealed relay metadata.
use crate::{Error, Principal, RelayProtocolLimits, dictionary_fingerprint, mtp_error};
use mtp::codec::{CommunicationValue, DataType, DataValue, MtpProtectionPurpose, TypeMap};
use mtp::crypto::Keyring;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRelayRoute {
    pub signer: Principal,
    pub recipient: Principal,
    pub destination: String,
    pub type_map_version: String,
    pub type_map_fingerprint: String,
}

impl NativeRelayRoute {
    pub fn validate(&self, map: &TypeMap) -> Result<(), Error> {
        self.signer.validate()?;
        self.recipient.validate()?;
        crate::validate_destination(&self.destination)?;
        if self.signer == self.recipient
            || self.type_map_version != map.version.to_string()
            || dictionary_fingerprint(&self.type_map_version)? != self.type_map_fingerprint
        {
            return Err(Error::Invalid("native relay routing identity"));
        }
        Ok(())
    }

    pub fn to_metadata(&self, map: &TypeMap) -> Result<DataValue, Error> {
        self.validate(map)?;
        Ok(DataValue::Bytes(serde_json::to_vec(self)?))
    }

    pub fn from_metadata(value: &DataValue, map: &TypeMap) -> Result<Self, Error> {
        let DataValue::Bytes(bytes) = value else {
            return Err(Error::Invalid("native relay routing metadata"));
        };
        if bytes.len() > 2048 {
            return Err(Error::Invalid("native relay routing metadata size"));
        }
        let route: Self = serde_json::from_slice(bytes)?;
        route.validate(map)?;
        if serde_json::to_vec(&route)? != *bytes {
            return Err(Error::Invalid("noncanonical native relay routing metadata"));
        }
        Ok(route)
    }
}

/// Decrypt claims solely to select pinned keys. The caller must verify the
/// original metadata signature and compare its authenticated route before use.
pub fn unverified_native_route(
    frame: &CommunicationValue,
    keyring: &Keyring,
) -> Result<NativeRelayRoute, Error> {
    let map = frame
        .type_map()
        .ok_or(Error::Invalid("missing native relay map"))?;
    let limits = RelayProtocolLimits::default();
    let decrypted = frame
        .payload()
        .decrypt_with_keyrings_and_limits(
            &[keyring],
            MtpProtectionPurpose::RelayMetadataEncryption.into(),
            limits.decode(limits.max_protected_bytes),
        )
        .map_err(mtp_error)?;
    let signed = decrypted
        .as_signed()
        .ok_or(Error::Invalid("unsigned native relay metadata"))?;
    let metadata = signed
        .value
        .get_field(
            DataType::Metadata
                .try_to_id(map)
                .ok_or(Error::Invalid("missing native metadata field"))?,
        )
        .ok_or(Error::Invalid("missing canonical native route"))?;
    NativeRelayRoute::from_metadata(metadata, map)
}
