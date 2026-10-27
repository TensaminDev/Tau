use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue, TypeMap};
use tau::sync::*;

fn scope() -> Scope {
    Scope {
        principal: tau::relay_protocol::Principal::new(format!("omega-key:{}", "a".repeat(64)), 42)
            .unwrap(),
        device_id: "device-a".into(),
        authorization_generation: 1,
        schema: SCHEMA.into(),
        dictionary: tau::relay_protocol::dictionary_fingerprint("1.0").unwrap(),
    }
}

#[test]
fn request_variants_have_exact_response_types_and_scope() {
    let map = TypeMap::new(mtp::type_map::Version(1, 0));
    let scope = scope();
    let cursor = Cursor {
        scope: scope.clone(),
        sequence: 7,
    };
    let page_id = "00000000-0000-4000-8000-000000000001".to_string();
    for (request, response) in [
        (
            Request::Snapshot {
                scope: scope.clone(),
                page: None,
                limit: 128,
            },
            Response::Snapshot {
                scope: scope.clone(),
                head: 7,
                floor: 0,
                page_id: page_id.clone(),
                next: None,
                records: vec![],
            },
        ),
        (
            Request::Delta {
                after: cursor.clone(),
                page: None,
                limit: 128,
            },
            Response::Delta {
                scope: scope.clone(),
                head: 7,
                floor: 0,
                page_id: page_id.clone(),
                next: None,
                events: vec![],
            },
        ),
        (
            Request::Acknowledge {
                cursor: cursor.clone(),
                page_id,
            },
            Response::Acknowledged { cursor },
        ),
    ] {
        let frame = encode_request(&request, &map, 9).unwrap();
        assert_eq!(
            serde_json::to_vec(&decode_request(&frame).unwrap()).unwrap(),
            serde_json::to_vec(&request).unwrap()
        );
        let reply = encode_response(&frame, &response).unwrap();
        decode_response(&reply, &frame).unwrap();
        assert!(decode_response(&reply.clone().with_id(10), &frame).is_err());
        assert!(
            decode_response(
                &CommunicationValue::new_with_type_map(CommunicationType::Success, &map)
                    .with_id(9)
                    .with_payload(reply.payload().clone()),
                &frame
            )
            .is_err()
        );
    }
}

#[test]
fn codecs_reject_extra_duplicate_malformed_and_wrong_dictionary_fields() {
    let map = TypeMap::new(mtp::type_map::Version(1, 0));
    let request = Request::Snapshot {
        scope: scope(),
        page: None,
        limit: 1,
    };
    let frame = encode_request(&request, &map, 9).unwrap();
    let mut fields = frame.payload().clone();
    let field = fields.container_entries().unwrap()[0].clone();
    fields.container_entries_mut().unwrap().push(field);
    assert!(decode_request(&frame.clone().with_payload(fields)).is_err());
    assert!(
        decode_request(
            &frame
                .clone()
                .add_typed_default(DataType::UserId, DataValue::UnsignedNumber(42))
        )
        .is_err()
    );
    assert!(
        decode_request(
            &frame
                .clone()
                .with_data(DataType::Json, DataValue::Bytes(vec![b'x'; 4097]))
        )
        .is_err()
    );
    let mut json = serde_json::to_string(&request).unwrap();
    json.insert_str(1, "\"unexpected\":true,");
    assert!(
        decode_request(&frame.with_data(DataType::Json, DataValue::Bytes(json.into_bytes())))
            .is_err()
    );
    assert!(encode_request(&request, &TypeMap::new(mtp::type_map::Version(99, 0)), 9).is_err());
}

#[test]
fn backend_golden_request_bytes_are_stable() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../relay-protocol/tests/fixtures/backend-sync.json"
    ))
    .unwrap();
    let request: Request = serde_json::from_value(vector["request"].clone()).unwrap();
    let map = TypeMap::new(mtp::type_map::Version(1, 0));
    assert_eq!(
        map.fingerprint_hex().as_deref(),
        vector["dictionary_fingerprint"].as_str()
    );
    let frame = encode_request(&request, &map, 42).unwrap();
    assert_eq!(
        STANDARD.encode(frame.to_bytes().unwrap()),
        vector["request_mtp_base64"].as_str().unwrap()
    );
}
