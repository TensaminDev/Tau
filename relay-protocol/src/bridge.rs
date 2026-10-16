//! Byte/string boundary shared by native tests and the WASM exports.
use super::*;

pub fn public_keys(json: &str) -> Result<Vec<PublicKeyBundle>, Error> {
    public_keys_with_limits(json, &RelayProtocolLimits::default())
}

/// General key-list parser uses the recipient-list bound. Verification bridges use the signer bound.
pub fn public_keys_with_limits(
    json: &str,
    limits: &RelayProtocolLimits,
) -> Result<Vec<PublicKeyBundle>, Error> {
    parse_public_keys(
        json,
        limits.max_recipient_keys.min(mtp::crypto::MAX_RECIPIENTS),
        limits,
    )
}

fn parse_public_keys(
    json: &str,
    max_keys: usize,
    limits: &RelayProtocolLimits,
) -> Result<Vec<PublicKeyBundle>, Error> {
    use mtp::crypto::keypair::{KEM_PUBLIC_KEY_LEN, SIG_CL_PUBLIC_KEY_LEN, SIG_PQ_PUBLIC_KEY_LEN};
    // Three u16-prefixed, fixed-suite public keys.
    const RAW_BYTES: usize = 6 + KEM_PUBLIC_KEY_LEN + SIG_PQ_PUBLIC_KEY_LEN + SIG_CL_PUBLIC_KEY_LEN;
    let encoded_bytes = limits::base64_len(RAW_BYTES);
    let max_json = max_keys
        .saturating_mul(encoded_bytes.saturating_mul(6).saturating_add(3))
        .saturating_add(1024)
        .min(limits.max_wire_bytes);
    preflight_json(
        json.as_bytes(),
        max_json,
        limits,
        Some((max_keys, encoded_bytes)),
    )?;
    let encoded: Vec<String> = serde_json::from_str(json)?;
    bound("key-list count", encoded.len(), max_keys)?;
    encoded
        .iter()
        .map(|key| {
            let bytes = decode_base64(key, "public-key bytes", RAW_BYTES)?;
            check_key_fields(
                &bytes,
                &[
                    KEM_PUBLIC_KEY_LEN,
                    SIG_PQ_PUBLIC_KEY_LEN,
                    SIG_CL_PUBLIC_KEY_LEN,
                ],
                true,
            )?;
            PublicKeyBundle::from_bytes(&bytes).map_err(mtp_error)
        })
        .collect()
}

// Check the length-prefixed layout before MTP copies fields or validates crypto material.
fn check_key_fields(bytes: &[u8], lengths: &[usize], exact: bool) -> Result<(), Error> {
    let mut offset = 0;
    for &max in lengths {
        let prefix = bytes
            .get(offset..offset + 2)
            .ok_or(Error::Invalid("raw key layout"))?;
        let len = u16::from_be_bytes([prefix[0], prefix[1]]) as usize;
        bound("raw key field bytes", len, max)?;
        if exact && len != max {
            return Err(Error::Invalid("public-key field length"));
        }
        offset += 2;
        bytes
            .get(offset..offset + len)
            .ok_or(Error::Invalid("raw key layout"))?;
        offset += len;
    }
    if offset != bytes.len() {
        return Err(Error::Invalid("trailing raw key bytes"));
    }
    Ok(())
}

fn keyring(bytes: &[u8]) -> Result<Keyring, Error> {
    // MTP's raw keyring permits six u16-length fields, including role-specific partial keys.
    let max = usize::from(u16::MAX);
    bound("keyring bytes", bytes.len(), 6 * (2 + max))?;
    check_key_fields(bytes, &[max; 6], false)?;
    Keyring::from_bytes(bytes).map_err(mtp_error)
}

pub(crate) fn principal(json: &str, limits: &RelayProtocolLimits) -> Result<Principal, Error> {
    let max = limits
        .max_authority_bytes
        .saturating_mul(6)
        .saturating_add(128)
        .min(limits.max_wire_bytes);
    preflight_json(json.as_bytes(), max, limits, None)?;
    let principal: Principal = serde_json::from_str(json)?;
    bound(
        "authority bytes",
        principal.authority.len(),
        limits.max_authority_bytes,
    )?;
    Ok(principal)
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
    sign_protected_bytes_with_limits(
        signer_json,
        recipient_json,
        destination,
        message_id,
        created_at,
        type_map_version,
        application_bytes,
        keyring_bytes,
        recipient_keys_json,
        &RelayProtocolLimits::default(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn sign_protected_bytes_with_limits(
    signer_json: &str,
    recipient_json: &str,
    destination: &str,
    message_id: &str,
    created_at: u64,
    type_map_version: &str,
    application_bytes: &[u8],
    keyring_bytes: &[u8],
    recipient_keys_json: &str,
    limits: &RelayProtocolLimits,
) -> Result<Vec<u8>, Error> {
    bound(
        "destination bytes",
        destination.len(),
        limits.max_destination_bytes,
    )?;
    bound(
        "message ID bytes",
        message_id.len(),
        limits.max_message_id_bytes,
    )?;
    bound(
        "type-map version bytes",
        type_map_version.len(),
        limits.max_type_map_version_bytes,
    )?;
    let signer = principal(signer_json, limits)?;
    let recipient = principal(recipient_json, limits)?;
    let application = decode_frame(
        application_bytes,
        &parse_map(type_map_version)?,
        limits.max_application_bytes,
        limits,
    )?;
    sign_protected_with_limits(
        signer,
        recipient,
        destination.to_owned(),
        message_id.to_owned(),
        created_at,
        application,
        &keyring(keyring_bytes)?,
        public_keys_with_limits(recipient_keys_json, limits)?,
        limits,
    )?
    .to_json_with_limits(limits)
}

pub fn verify_and_open_bytes(
    wire_json: &[u8],
    signer_keys_json: &str,
    keyring_bytes: &[u8],
    expected_recipient_json: &str,
    expected_destination: &str,
) -> Result<Vec<u8>, Error> {
    verify_and_open_bytes_with_limits(
        wire_json,
        signer_keys_json,
        keyring_bytes,
        expected_recipient_json,
        expected_destination,
        &RelayProtocolLimits::default(),
    )
}

pub fn verify_and_open_bytes_with_limits(
    wire_json: &[u8],
    signer_keys_json: &str,
    keyring_bytes: &[u8],
    expected_recipient_json: &str,
    expected_destination: &str,
    limits: &RelayProtocolLimits,
) -> Result<Vec<u8>, Error> {
    preflight_json(wire_json, limits.max_wire_bytes, limits, None)?;
    bound(
        "destination bytes",
        expected_destination.len(),
        limits.max_destination_bytes,
    )?;
    let recipient = principal(expected_recipient_json, limits)?;
    verify_and_open_with_limits(
        wire_json,
        &parse_public_keys(signer_keys_json, limits.max_signer_keys, limits)?,
        &keyring(keyring_bytes)?,
        Some(&recipient),
        Some(expected_destination),
        limits,
    )?
    .application
    .to_bytes_with_limits(limits.encode(limits.max_application_bytes))
    .map_err(mtp_error)
}
