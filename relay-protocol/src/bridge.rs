//! Byte/string boundary shared by native tests and the WASM exports.
use super::*;

pub fn public_keys(json: &str) -> Result<Vec<PublicKeyBundle>, Error> {
    let encoded: Vec<String> = serde_json::from_str(json)?;
    encoded
        .iter()
        .map(|key| PublicKeyBundle::from_bytes(&STANDARD.decode(key)?).map_err(mtp_error))
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub fn sign_protected_bytes(
    signer_json: &str,
    recipient_json: &str,
    destination: &str,
    message_id: &str,
    created_at: u64,
    type_map_version: &str,
    application_bytes: &[u8],
    keyring_bytes: &[u8],
    recipient_keys_json: &str,
) -> Result<Vec<u8>, Error> {
    let application =
        CommunicationValue::from_bytes_with(application_bytes, &parse_map(type_map_version)?)
            .map_err(mtp_error)?;
    sign_protected(
        serde_json::from_str(signer_json)?,
        serde_json::from_str(recipient_json)?,
        destination.to_owned(),
        message_id.to_owned(),
        created_at,
        application,
        &Keyring::from_bytes(keyring_bytes).map_err(mtp_error)?,
        public_keys(recipient_keys_json)?,
    )?
    .to_json()
}

pub fn verify_and_open_bytes(
    wire_json: &[u8],
    signer_keys_json: &str,
    keyring_bytes: &[u8],
    expected_recipient_json: &str,
    expected_destination: &str,
) -> Result<Vec<u8>, Error> {
    let recipient: Principal = serde_json::from_str(expected_recipient_json)?;
    verify_and_open(
        wire_json,
        &public_keys(signer_keys_json)?,
        &Keyring::from_bytes(keyring_bytes).map_err(mtp_error)?,
        Some(&recipient),
        Some(expected_destination),
    )?
    .application
    .to_bytes()
    .map_err(mtp_error)
}
