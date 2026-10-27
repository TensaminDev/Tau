//! Run against the backend map: cargo run --example export_dictionary.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use mtp::type_map::{TypeMap, Version};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let map = TypeMap::new(Version(1, 0));
    let bytes = map
        .dictionary_bytes()
        .ok_or("backend dictionary 1.0 is not compiled in")?;
    let sync_scope = tau_relay_protocol::sync::Scope {
        principal: tau_relay_protocol::Principal::new(format!("omega-key:{}", "a".repeat(64)), 42)?,
        device_id: "fixture-device".into(),
        authorization_generation: 1,
        schema: tau_relay_protocol::sync::SCHEMA.into(),
        dictionary: map.fingerprint_hex().ok_or("missing fingerprint")?,
    };
    let sync_request = tau_relay_protocol::sync::Request::Snapshot {
        scope: sync_scope,
        page: None,
        limit: 128,
    };
    let sync_json = serde_json::to_vec(&sync_request)?;
    let sync_frame = mtp::codec::CommunicationValue::new_with_type_map(
        mtp::codec::CommunicationType::from_name("AccountStateRequest").ok_or("run with the backend dictionary")?,
        &map,
    )
    .with_id(42)
    .add_typed_default(
        mtp::codec::DataType::from_name("Json").ok_or("run with the backend dictionary")?,
        mtp::codec::DataValue::Bytes(sync_json.clone()),
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "version": "1.0",
            "fingerprint_algorithm": "sha256",
            "serialization": "mtp-type-dictionary-v1",
            "fingerprint": map.fingerprint_hex().ok_or("missing dictionary fingerprint")?,
            "canonical_dictionary_base64": STANDARD.encode(bytes),
            "principal": { "authority_formats": ["omega-key:<64 lowercase hexadecimal digits>", "authority:iota:v1:<64 lowercase hexadecimal digits>"], "user_id_min": 1, "user_id_max": i64::MAX.to_string() },
            "chat_id": "principal:<unpadded base64url of the sorted canonical principal JSON array>",
            "secret_id": "chat:{chat_id}:main",
            "sync": {
                "schema":tau_relay_protocol::sync::SCHEMA,
                "request_type":"AccountStateRequest", "response_type":"AccountStateSnapshot", "payload":"exactly one Json byte field containing UTF-8 JSON",
                "scope_fields":["principal","device_id","authorization_generation","schema","dictionary"],
                "request_variants":["snapshot","delta","acknowledge"],
                "response_variants":["snapshot","delta","acknowledged","unavailable"],
                "errors":["snapshot_required","identity_changed","retryable","unauthorized","invalid_request","capacity"],
                "page_limit":tau_relay_protocol::sync::PAGE_LIMIT,"page_bytes":tau_relay_protocol::sync::PAGE_BYTES,
                "checkpoint_rule":"only an explicit complete-page acknowledgement advances the device checkpoint",
                "record_encoding":"SQLite integer columns are decimal strings; byte columns are objects with one base64 string field; wrapping ciphertext is fetched by canonical Chat Secret read",
                "golden_request_json":serde_json::from_slice::<serde_json::Value>(&sync_json)?,
                "golden_request_mtp_base64":STANDARD.encode(sync_frame.to_bytes()?)
            }
        }))?
    );
    Ok(())
}
