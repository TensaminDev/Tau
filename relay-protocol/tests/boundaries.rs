use base64::{Engine as _, engine::general_purpose::STANDARD};
use mtp::{
    codec::{CommunicationType, CommunicationValue, DataValue, TypeMap},
    crypto::{DualSigner, Keyring, SigAlgorithm, SignatureScheme},
};
use tau_relay_protocol::*;

fn principal(authority: &str, user_id: u64) -> Principal {
    Principal {
        authority: format!("omega-key:{}", authority.repeat(64)),
        user_id,
    }
}

// Structurally valid, deliberately unsigned. Public parsing must not perform crypto.
fn wire() -> RelayWire {
    RelayWire {
        signer: principal("a", 1),
        recipient: principal("b", 2),
        destination: format!("iota:v1:{}", "a".repeat(64)),
        message_id: "opaque".into(),
        created_at: 0,
        type_map_version: "3.0".into(),
        type_map_fingerprint: TypeMap::new(mtp::type_map::Version(3, 0))
            .fingerprint_hex()
            .unwrap(),
        content: STANDARD.encode([1, 2, 3]),
        signature: STANDARD.encode(vec![0; SigAlgorithm::length(SigAlgorithm::DUAL).unwrap()]),
    }
}

fn limit<T: std::fmt::Debug>(result: Result<T, Error>, field: &str, actual: usize, max: usize) {
    match result {
        Err(Error::Limit {
            field: got,
            actual: n,
            max: m,
        }) => {
            assert_eq!((got, n, m), (field, actual, max));
        }
        other => panic!("expected {field} limit {actual} > {max}, got {other:?}"),
    }
}

fn app(payload: DataValue) -> CommunicationValue {
    CommunicationValue::new_with_type_map(CommunicationType::MessageSend, &TypeMap::latest())
        .with_id(7)
        .with_payload(payload)
}

fn sign(application: CommunicationValue, sender: &Keyring, recipient: &Keyring) -> RelayWire {
    sign_protected(
        principal("a", 1),
        principal("b", 2),
        wire().destination,
        "opaque".into(),
        42,
        application,
        sender,
        vec![recipient.public_key_bundle()],
    )
    .unwrap()
}

// An invalid keyring is a sentinel proving that application decoding completed first.
fn bridge_decode(application: &[u8], limits: &RelayProtocolLimits) -> Result<Vec<u8>, Error> {
    bridge::sign_protected_bytes_with_limits(
        r#"{"authority":"omega-key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","user_id":1}"#,
        r#"{"authority":"omega-key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","user_id":2}"#,
        &wire().destination,
        "opaque",
        42,
        "3.0",
        application,
        &[],
        "[]",
        limits,
    )
}

#[test]
fn public_wire_boundaries_include_serialized_bytes_and_json_structure() {
    let mut wire = wire();
    wire.message_id = "[{},\"escaped\"]".into();
    let json = serde_json::to_vec(&wire).unwrap();
    let limits = RelayProtocolLimits {
        max_wire_bytes: json.len(),
        max_depth: 2,
        max_fields: 27,
        ..RelayProtocolLimits::default()
    };
    wire.validate_with_limits(&limits).unwrap();
    assert_eq!(wire.to_json_with_limits(&limits).unwrap(), json);
    assert_eq!(
        RelayWire::from_json_with_limits(&json, &limits)
            .unwrap()
            .signer,
        wire.signer
    );
    RelayWire::from_json(&json).unwrap().validate().unwrap();
    for limits in [
        RelayProtocolLimits {
            max_wire_bytes: json.len() - 1,
            ..limits
        },
        RelayProtocolLimits {
            max_depth: 1,
            ..limits
        },
        RelayProtocolLimits {
            max_fields: 26,
            ..limits
        },
    ] {
        let (field, actual, max) = if limits.max_depth == 1 {
            ("JSON depth", 2, 1)
        } else if limits.max_fields == 26 {
            ("JSON fields", 27, 26)
        } else {
            ("JSON bytes", json.len(), json.len() - 1)
        };
        limit(wire.validate_with_limits(&limits), field, actual, max);
        limit(wire.to_json_with_limits(&limits), field, actual, max);
        limit(
            RelayWire::from_json_with_limits(&json, &limits),
            field,
            actual,
            max,
        );
    }
    let mut padded = json.clone();
    padded.push(b' ');
    limit(
        RelayWire::from_json_with_limits(
            &padded,
            &RelayProtocolLimits {
                max_wire_bytes: json.len(),
                ..RelayProtocolLimits::default()
            },
        ),
        "JSON bytes",
        json.len() + 1,
        json.len(),
    );
}

#[test]
fn principal_and_identity_limits_measure_utf8_bytes() {
    let mut wire = wire();
    wire.message_id = "💬💬".into();
    let limits = RelayProtocolLimits {
        max_authority_bytes: wire.signer.authority.len(),
        max_message_id_bytes: 8,
        max_destination_bytes: wire.destination.len(),
        max_type_map_version_bytes: 3,
        ..RelayProtocolLimits::default()
    };
    wire.validate_with_limits(&limits).unwrap();
    for field in [
        "signer",
        "recipient",
        "message_id",
        "destination",
        "type_map_version",
    ] {
        let mut changed = wire.clone();
        let (label, max) = match field {
            "signer" => {
                changed.signer.authority.push('x');
                ("authority bytes", limits.max_authority_bytes)
            }
            "recipient" => {
                changed.recipient.authority.push('x');
                ("authority bytes", limits.max_authority_bytes)
            }
            "message_id" => {
                changed.message_id.push('x');
                ("message ID bytes", 8)
            }
            "destination" => {
                changed.destination.push('x');
                ("destination bytes", 72)
            }
            _ => {
                changed.type_map_version.push('x');
                ("type-map version bytes", 3)
            }
        };
        limit(changed.validate_with_limits(&limits), label, max + 1, max);
        let decoded =
            RelayWire::from_json_with_limits(&serde_json::to_vec(&changed).unwrap(), &limits);
        if field == "signer" || field == "recipient" {
            assert!(decoded.is_err());
        } else {
            limit(decoded, label, max + 1, max);
        }
        limit(
            canonical_bytes_with_limits(&changed, b"", &limits),
            label,
            max + 1,
            max,
        );
    }
}

#[test]
fn public_wire_rejects_semantic_and_schema_errors() {
    let original = wire();
    for field in [
        "signer",
        "recipient",
        "identical",
        "destination",
        "uppercase",
        "message_id",
        "unknown_map",
        "noncanonical_map",
    ] {
        let mut changed = original.clone();
        match field {
            "signer" => changed.signer.authority = " \t\n".into(),
            "recipient" => changed.recipient.authority.clear(),
            "identical" => changed.recipient = changed.signer.clone(),
            "destination" => changed.destination = "iota:v1:a".into(),
            "uppercase" => changed.destination = format!("iota:v1:{}", "A".repeat(64)),
            "message_id" => changed.message_id.clear(),
            "unknown_map" => changed.type_map_version = "99.0".into(),
            _ => changed.type_map_version = "03.0".into(),
        }
        assert!(
            matches!(changed.validate(), Err(Error::Invalid(_))),
            "{field}"
        );
        assert!(changed.to_json().is_err(), "{field}");
        assert!(
            RelayWire::from_json(&serde_json::to_vec(&changed).unwrap()).is_err(),
            "{field}"
        );
    }
    let mut value = serde_json::to_value(&original).unwrap();
    value["unexpected"] = true.into();
    assert!(RelayWire::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
    value.as_object_mut().unwrap().remove("unexpected");
    value["signer"]["unexpected"] = true.into();
    assert!(RelayWire::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
    let json = String::from_utf8(serde_json::to_vec(&original).unwrap()).unwrap();
    assert!(RelayWire::from_json(json.replacen("{", "{\"version\":2,", 1).as_bytes()).is_err());
    assert!(RelayWire::from_json(format!("{json} null").as_bytes()).is_err());
}

#[test]
fn federation_frame_rejects_legacy_and_unsigned_outer_metadata() {
    use mtp::codec::DataType;
    let frame = wire().into_frame(7).unwrap();
    RelayWire::from_frame(&frame).unwrap();
    for field in [DataType::VersionNumber, DataType::Description] {
        assert!(
            RelayWire::from_frame(
                &frame
                    .clone()
                    .add_typed_default(field, DataValue::UnsignedNumber(2))
            )
            .is_err()
        );
    }
    assert!(RelayWire::from_frame(&frame.clone().with_sender(1)).is_err());
    assert!(RelayWire::from_frame(&frame.clone().with_receiver(2)).is_err());
    let mut value = serde_json::to_value(wire()).unwrap();
    value["version"] = 2.into();
    let legacy =
        CommunicationValue::new_with_type_map(CommunicationType::Relay, frame.type_map().unwrap())
            .add_typed_default(
                DataType::SecurePayload,
                DataValue::Bytes(serde_json::to_vec(&value).unwrap()),
            );
    assert!(RelayWire::from_frame(&legacy).is_err());
}

#[test]
fn base64_boundaries_check_decoded_size_even_within_encoded_budget() {
    let mut bounded = wire();
    let limits = RelayProtocolLimits {
        max_protected_bytes: 4,
        ..RelayProtocolLimits::default()
    };
    bounded.content = STANDARD.encode([0; 4]);
    bounded.validate_with_limits(&limits).unwrap();
    bounded.content = STANDARD.encode([0; 5]);
    assert_eq!(bounded.content.len(), STANDARD.encode([0; 4]).len());
    limit(
        bounded.validate_with_limits(&limits),
        "protected bytes",
        5,
        4,
    );
    limit(
        RelayWire::from_json_with_limits(&serde_json::to_vec(&bounded).unwrap(), &limits),
        "protected bytes",
        5,
        4,
    );
    bounded.content = STANDARD.encode([0; 7]);
    assert!(matches!(
        bounded.validate_with_limits(&limits),
        Err(Error::Limit { .. })
    ));
    for invalid in [
        "!AAA", "Zg", "Zg=", "Zg===", "Zh==", "AA=A", "====", "AA-_", "AA==\n",
    ] {
        let mut changed = wire();
        changed.content = invalid.into();
        assert!(changed.validate().is_err(), "content {invalid:?}");
        changed = wire();
        changed.signature = invalid.into();
        assert!(changed.validate().is_err(), "signature {invalid:?}");
    }
    let mut wire = wire();
    let signature_len = SigAlgorithm::length(SigAlgorithm::DUAL).unwrap();
    for n in [0, signature_len - 1, signature_len + 1] {
        wire.signature = STANDARD.encode(vec![0; n]);
        assert!(wire.validate().is_err(), "signature length {n}");
    }
}

#[test]
fn preflight_limits_win_over_json_deserialization_and_crypto() {
    let limits = RelayProtocolLimits {
        max_wire_bytes: 3,
        ..RelayProtocolLimits::default()
    };
    limit(
        verify_outer_with_limits(b"xxxx", &[], None, None, &limits),
        "JSON bytes",
        4,
        3,
    );
    let limits = RelayProtocolLimits {
        max_depth: 2,
        ..RelayProtocolLimits::default()
    };
    limit(
        RelayWire::from_json_with_limits(b"[[[", &limits),
        "JSON depth",
        3,
        2,
    );
    let limits = RelayProtocolLimits {
        max_fields: 2,
        ..RelayProtocolLimits::default()
    };
    limit(
        RelayWire::from_json_with_limits(b"[0,0]", &limits),
        "JSON fields",
        3,
        2,
    );
    let sender = Keyring::generate();
    let limits = RelayProtocolLimits {
        max_signer_keys: 1,
        ..RelayProtocolLimits::default()
    };
    // Invalid JSON and signatures must not hide an overlong signer history.
    limit(
        verify_outer_with_limits(
            b"{}",
            &[sender.public_key_bundle(), sender.public_key_bundle()],
            None,
            None,
            &limits,
        ),
        "signer keys",
        2,
        1,
    );
    let mut changed = wire();
    changed.signer.authority = "x".repeat(1025);
    assert!(
        verify_outer(
            &serde_json::to_vec(&changed).unwrap(),
            &[sender.public_key_bundle()],
            None,
            None,
        )
        .is_err()
    );
}

#[test]
fn bridge_application_decode_enforces_exact_depth_fields_and_allocations() {
    let mut nested = DataValue::Null;
    for _ in 0..4 {
        nested = DataValue::Array(vec![nested]);
    }
    let bytes = app(nested).to_bytes().unwrap();
    let limits = RelayProtocolLimits {
        max_depth: 4,
        ..RelayProtocolLimits::default()
    };
    assert!(matches!(
        bridge_decode(&bytes, &limits),
        Err(Error::Invalid("raw key layout"))
    ));
    assert!(matches!(
        bridge_decode(
            &bytes,
            &RelayProtocolLimits {
                max_depth: 3,
                ..limits
            }
        ),
        Err(Error::Mtp(_))
    ));

    // Principal JSON consumes five tokens. This application has six value nodes.
    let bytes = app(DataValue::Array(vec![DataValue::Null; 5]))
        .to_bytes()
        .unwrap();
    let limits = RelayProtocolLimits {
        max_fields: 6,
        ..RelayProtocolLimits::default()
    };
    assert!(matches!(
        bridge_decode(&bytes, &limits),
        Err(Error::Invalid("raw key layout"))
    ));
    assert!(matches!(
        bridge_decode(
            &bytes,
            &RelayProtocolLimits {
                max_fields: 5,
                ..limits
            }
        ),
        Err(Error::Mtp(_))
    ));

    let bytes = app(DataValue::Str("é".into())).to_bytes().unwrap();
    let limits = RelayProtocolLimits {
        max_allocated_bytes: 2,
        max_application_bytes: bytes.len(),
        ..RelayProtocolLimits::default()
    };
    assert!(matches!(
        bridge_decode(&bytes, &limits),
        Err(Error::Invalid("raw key layout"))
    ));
    assert!(matches!(
        bridge_decode(
            &bytes,
            &RelayProtocolLimits {
                max_allocated_bytes: 1,
                ..limits
            }
        ),
        Err(Error::Mtp(_))
    ));
    limit(
        bridge_decode(
            &bytes,
            &RelayProtocolLimits {
                max_application_bytes: bytes.len() - 1,
                ..limits
            },
        ),
        "MTP frame bytes",
        bytes.len(),
        bytes.len() - 1,
    );
    let bytes = app(DataValue::Array(vec![DataValue::Null]))
        .to_bytes()
        .unwrap();
    let allocation = std::mem::size_of::<DataValue>();
    let limits = RelayProtocolLimits {
        max_allocated_bytes: allocation,
        ..RelayProtocolLimits::default()
    };
    assert!(matches!(
        bridge_decode(&bytes, &limits),
        Err(Error::Invalid("raw key layout"))
    ));
    assert!(matches!(
        bridge_decode(
            &bytes,
            &RelayProtocolLimits {
                max_allocated_bytes: allocation - 1,
                ..limits
            }
        ),
        Err(Error::Mtp(_))
    ));
}

#[test]
fn bridge_principal_limits_apply_after_json_unescaping_before_key_parsing() {
    let bytes = app(DataValue::Null).to_bytes().unwrap();
    let destination = wire().destination;
    let limits = RelayProtocolLimits {
        max_authority_bytes: 2,
        max_message_id_bytes: 1,
        max_type_map_version_bytes: 3,
        max_destination_bytes: destination.len(),
        ..RelayProtocolLimits::default()
    };
    for signer in [
        r#"{"authority":"é","user_id":1}"#,
        r#"{"authority":"\u00e9","user_id":1}"#,
        r#"{"authority":"\"\\","user_id":1}"#,
    ] {
        assert!(matches!(
            bridge::sign_protected_bytes_with_limits(
                signer,
                r#"{"authority":"omega-key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","user_id":2}"#,
                &destination,
                "x",
                0,
                "3.0",
                &bytes,
                &[],
                "[]",
                &limits,
            ),
            Err(Error::Json(_))
        ));
    }
    for (signer, recipient) in [
        (
            r#"{"authority":"\u00e9x","user_id":1}"#,
            r#"{"authority":"b","user_id":2}"#,
        ),
        (
            r#"{"authority":"a","user_id":1}"#,
            r#"{"authority":"\u00e9x","user_id":2}"#,
        ),
    ] {
        assert!(matches!(
            bridge::sign_protected_bytes_with_limits(
                signer,
                recipient,
                &destination,
                "x",
                0,
                "3.0",
                &bytes,
                &[],
                "[]",
                &limits,
            ),
            Err(Error::Json(_))
        ));
    }
    for (destination, message_id, version, label, actual, max) in [
        (
            format!("{destination}x"),
            "x",
            "3.0",
            "destination bytes",
            73,
            72,
        ),
        (destination.clone(), "xx", "3.0", "message ID bytes", 2, 1),
        (
            destination.clone(),
            "x",
            "03.0",
            "type-map version bytes",
            4,
            3,
        ),
    ] {
        limit(
            bridge::sign_protected_bytes_with_limits(
                "invalid JSON",
                "invalid JSON",
                &destination,
                message_id,
                0,
                version,
                &[],
                &[],
                "[]",
                &limits,
            ),
            label,
            actual,
            max,
        );
    }
}

#[test]
fn public_key_json_accepts_escapes_and_bounds_counts_and_raw_layout() {
    let key = Keyring::generate()
        .public_key_bundle()
        .try_as_bytes()
        .unwrap();
    let encoded = STANDARD.encode(&key);
    let json = serde_json::to_string(&[&encoded]).unwrap();
    let escaped = format!(
        "[\"{}\"]",
        encoded
            .bytes()
            .map(|b| format!("\\u{b:04x}"))
            .collect::<String>()
    );
    let limits = RelayProtocolLimits {
        max_recipient_keys: 1,
        max_depth: 1,
        max_fields: 2,
        max_wire_bytes: escaped.len(),
        ..RelayProtocolLimits::default()
    };
    for json in [&json, &escaped] {
        let parsed = bridge::public_keys_with_limits(json, &limits).unwrap();
        assert_eq!(parsed[0].try_as_bytes().unwrap(), key);
    }
    limit(
        bridge::public_keys_with_limits(
            &escaped,
            &RelayProtocolLimits {
                max_wire_bytes: escaped.len() - 1,
                ..limits
            },
        ),
        "JSON bytes",
        escaped.len(),
        escaped.len() - 1,
    );
    let two = serde_json::to_string(&[&encoded, &encoded]).unwrap();
    limit(
        bridge::public_keys_with_limits(
            &two,
            &RelayProtocolLimits {
                max_fields: 10,
                ..limits
            },
        ),
        "key-list count",
        2,
        1,
    );
    limit(
        bridge::public_keys_with_limits(
            &json,
            &RelayProtocolLimits {
                max_fields: 1,
                ..limits
            },
        ),
        "JSON fields",
        2,
        1,
    );
    assert!(bridge::public_keys("[]").unwrap().is_empty());
    for malformed in ["!AAA", "Zg", "Zh==", "AA=A"] {
        assert!(bridge::public_keys(&serde_json::to_string(&[malformed]).unwrap()).is_err());
    }
    for raw in [
        key[..key.len() - 1].to_vec(),
        [key.as_slice(), &[0]].concat(),
        {
            let mut bad = key.clone();
            bad[..2].copy_from_slice(&u16::MAX.to_be_bytes());
            bad
        },
    ] {
        assert!(
            bridge::public_keys(&serde_json::to_string(&[STANDARD.encode(raw)]).unwrap()).is_err()
        );
    }
    let oversized = serde_json::to_string(&["x".repeat(encoded.len() + 1)]).unwrap();
    assert!(matches!(
        bridge::public_keys(&oversized),
        Err(Error::Limit { .. })
    ));
}

#[test]
fn real_crypto_roundtrip_obeys_wire_protected_application_and_key_counts() {
    let sender = Keyring::generate();
    let recipient = Keyring::generate();
    let application = app(DataValue::Bytes(vec![7; 64]));
    let wire = sign(application.clone(), &sender, &recipient);
    let json = wire.to_json().unwrap();
    let protected = STANDARD.decode(&wire.content).unwrap();
    let limits = RelayProtocolLimits {
        max_wire_bytes: json.len(),
        max_protected_bytes: protected.len(),
        max_application_bytes: application.to_bytes().unwrap().len(),
        max_signer_keys: 1,
        max_recipient_keys: 1,
        ..RelayProtocolLimits::default()
    };
    let keys = [sender.public_key_bundle()];
    assert_eq!(
        verify_and_open_with_limits(&json, &keys, &recipient, None, None, &limits)
            .unwrap()
            .application,
        application
    );
    let key_json =
        serde_json::to_string(&[STANDARD.encode(keys[0].try_as_bytes().unwrap())]).unwrap();
    assert_eq!(
        bridge::verify_and_open_bytes_with_limits(
            &json,
            &key_json,
            &recipient.try_to_bytes().unwrap(),
            r#"{"authority":"omega-key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","user_id":2}"#,
            &wire.destination,
            &limits
        )
        .unwrap(),
        application.to_bytes().unwrap()
    );
    for smaller in [
        RelayProtocolLimits {
            max_wire_bytes: json.len() - 1,
            ..limits
        },
        RelayProtocolLimits {
            max_protected_bytes: protected.len() - 1,
            ..limits
        },
        RelayProtocolLimits {
            max_application_bytes: limits.max_application_bytes - 1,
            ..limits
        },
        RelayProtocolLimits {
            max_signer_keys: 0,
            ..limits
        },
        RelayProtocolLimits {
            max_recipient_keys: 0,
            ..limits
        },
        RelayProtocolLimits {
            max_allocated_bytes: 0,
            ..limits
        },
    ] {
        assert!(
            verify_and_open_with_limits(&json, &keys, &recipient, None, None, &smaller).is_err(),
            "{smaller:?}"
        );
    }
    let rotated = [
        Keyring::generate().public_key_bundle(),
        sender.public_key_bundle(),
    ];
    verify_outer_with_limits(
        &json,
        &rotated,
        None,
        None,
        &RelayProtocolLimits {
            max_signer_keys: 2,
            ..limits
        },
    )
    .unwrap();
    limit(
        verify_outer_with_limits(&json, &rotated, None, None, &limits),
        "signer keys",
        2,
        1,
    );
    let two = serde_json::to_string(&[
        STANDARD.encode(rotated[0].try_as_bytes().unwrap()),
        STANDARD.encode(rotated[1].try_as_bytes().unwrap()),
    ])
    .unwrap();
    limit(
        bridge::verify_and_open_bytes_with_limits(
            &json,
            &two,
            &[],
            r#"{"authority":"omega-key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","user_id":2}"#,
            &wire.destination,
            &limits,
        ),
        "key-list count",
        2,
        1,
    );
    limit(
        sign_protected_with_limits(
            principal("a", 1),
            principal("b", 2),
            wire.destination.clone(),
            "opaque".into(),
            42,
            application.clone(),
            &sender,
            vec![recipient.public_key_bundle(), sender.public_key_bundle()],
            &limits,
        ),
        "recipient keys",
        2,
        1,
    );
    assert!(matches!(
        sign_protected(
            principal("a", 1),
            principal("b", 2),
            wire.destination.clone(),
            "opaque".into(),
            42,
            application,
            &sender,
            vec![]
        ),
        Err(Error::Invalid("recipient keys"))
    ));

    let fixed = TypeMap::new(mtp::type_map::Version::parse(PROTECTED_TYPE_MAP_VERSION).unwrap());
    let protected_type = CommunicationType::from_name("ProtectedMessage").unwrap();
    assert_ne!(
        protected_type.try_to_id(&fixed),
        protected_type.try_to_id(&TypeMap::latest())
    );
    assert!(
        verify_outer(&json, &keys, None, None)
            .unwrap()
            .protected
            .is_type(protected_type)
    );
}

#[test]
fn signed_declared_application_map_never_falls_back_to_latest() {
    let sender = Keyring::generate();
    let recipient = Keyring::generate();
    let mut wire = sign(app(DataValue::Null), &sender, &recipient);
    wire.type_map_version = "1.0".into();
    assert!(
        wire.validate().is_err(),
        "a version label cannot substitute another dictionary"
    );
    wire.type_map_fingerprint = dictionary_fingerprint("1.0").unwrap();
    let signing = DualSigner::new(
        &sender.sig_cl_secret_key,
        &sender.sig_pq_secret_key,
        &sender.sig_pq_public_key,
    )
    .unwrap();
    wire.signature = STANDARD.encode(
        signing
            .sign(&canonical_bytes(&wire, &STANDARD.decode(&wire.content).unwrap()).unwrap())
            .unwrap(),
    );
    let json = serde_json::to_vec(&wire).unwrap();
    // The valid outer signature and fixed-map protected envelope still verify.
    verify_outer(&json, &[sender.public_key_bundle()], None, None).unwrap();
    let opened =
        verify_and_open(&json, &[sender.public_key_bundle()], &recipient, None, None).unwrap();
    assert_eq!(
        opened.application.type_map().unwrap().version.to_string(),
        "1.0"
    );
    assert!(!opened.application.is_type(CommunicationType::MessageSend));
}
