use super::*;
use wasm_bindgen::prelude::*;

fn js_error(error: Error) -> JsValue {
    JsValue::from_str(&error.to_string())
}

#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn relay_sign_protected(
    signer_json: &str,
    recipient_json: &str,
    destination: &str,
    message_id: &str,
    created_at: u64,
    type_map_version: &str,
    application_bytes: &[u8],
    keyring_bytes: &[u8],
    recipient_keys_json: &str,
) -> Result<Vec<u8>, JsValue> {
    bridge::sign_protected_bytes(
        signer_json,
        recipient_json,
        destination,
        message_id,
        created_at,
        type_map_version,
        application_bytes,
        keyring_bytes,
        recipient_keys_json,
    )
    .map_err(js_error)
}

#[wasm_bindgen]
pub fn relay_verify_and_open(
    wire_json: &[u8],
    signer_keys_json: &str,
    keyring_bytes: &[u8],
    expected_recipient_json: &str,
    expected_destination: &str,
) -> Result<Vec<u8>, JsValue> {
    bridge::verify_and_open_bytes(
        wire_json,
        signer_keys_json,
        keyring_bytes,
        expected_recipient_json,
        expected_destination,
    )
    .map_err(js_error)
}

#[wasm_bindgen]
pub fn relay_canonical_chat_id(first_json: &str, second_json: &str) -> Result<String, JsValue> {
    Ok(canonical_chat_id(
        &serde_json::from_str(first_json)
            .map_err(Error::from)
            .map_err(js_error)?,
        &serde_json::from_str(second_json)
            .map_err(Error::from)
            .map_err(js_error)?,
    ))
}

#[wasm_bindgen]
pub fn relay_chat_participants(first_json: &str, second_json: &str) -> Result<String, JsValue> {
    let participants = canonical_chat_participants(
        &serde_json::from_str(first_json)
            .map_err(Error::from)
            .map_err(js_error)?,
        &serde_json::from_str(second_json)
            .map_err(Error::from)
            .map_err(js_error)?,
    );
    serde_json::to_string(&participants)
        .map_err(Error::from)
        .map_err(js_error)
}

#[wasm_bindgen]
pub fn relay_chat_secret_id(chat_id: &str) -> String {
    chat_secret_id(chat_id)
}
