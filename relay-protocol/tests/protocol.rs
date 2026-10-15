use base64::{Engine as _, engine::general_purpose::STANDARD};
use mtp::{
    codec::{CommunicationType, CommunicationValue, DataType, DataValue, TypeMap},
    crypto::{DualSigner, Keyring, SignatureScheme},
};
use tau_relay_protocol::*;

fn principal(authority: &str, user_id: u64) -> Principal {
    Principal {
        authority: authority.into(),
        user_id,
    }
}
fn destination() -> String {
    format!("iota:v1:{}", "a".repeat(64))
}
fn application() -> CommunicationValue {
    CommunicationValue::new_with_type_map(CommunicationType::MessageSend, &TypeMap::latest())
        .add_typed_default(
            DataType::ChatId,
            DataValue::Str("private chat metadata".into()),
        )
        .add_typed_default(
            DataType::SecretId,
            DataValue::Str("private secret metadata".into()),
        )
        .add_typed_default(
            DataType::Content,
            DataValue::Str("application ciphertext".into()),
        )
}
fn resign(wire: &mut RelayWire, keyring: &Keyring) {
    let signer = DualSigner::new(
        &keyring.sig_cl_secret_key,
        &keyring.sig_pq_secret_key,
        &keyring.sig_pq_public_key,
    )
    .unwrap();
    wire.signature = STANDARD.encode(
        signer
            .sign(&canonical_bytes(wire, &STANDARD.decode(&wire.content).unwrap()).unwrap())
            .unwrap(),
    );
}

#[test]
fn confidential_roundtrip_and_browser_boundary() {
    let sender = Keyring::generate();
    let recipients = [
        Keyring::generate(),
        Keyring::generate(),
        Keyring::generate(),
    ];
    let signer = principal("authority:a", 7);
    let recipient = principal("authority:b", 7);
    let app = application();
    let keys = recipients.iter().map(Keyring::public_key_bundle).collect();
    let wire = sign_protected(
        signer.clone(),
        recipient.clone(),
        destination(),
        "opaque-message".into(),
        42,
        app.clone(),
        &sender,
        keys,
    )
    .unwrap();
    let json = wire.to_json().unwrap();
    let encrypted = STANDARD.decode(&wire.content).unwrap();
    for secret in [
        "private chat metadata",
        "private secret metadata",
        "application ciphertext",
    ] {
        assert!(!json.windows(secret.len()).any(|w| w == secret.as_bytes()));
        assert!(
            !encrypted
                .windows(secret.len())
                .any(|w| w == secret.as_bytes())
        );
    }
    let signer_keys = [sender.public_key_bundle()];
    for key in &recipients {
        let opened = verify_and_open(
            &json,
            &signer_keys,
            key,
            Some(&recipient),
            Some(&destination()),
        )
        .unwrap();
        assert_eq!(
            opened.application.to_bytes().unwrap(),
            app.to_bytes().unwrap()
        );
    }
    assert!(verify_and_open(&json, &signer_keys, &Keyring::generate(), None, None).is_err());
    assert!(verify_and_open(&json, &signer_keys, &recipients[0], Some(&signer), None).is_err());
    let bundle_json = serde_json::to_string(&vec![
        STANDARD.encode(signer_keys[0].try_as_bytes().unwrap()),
    ])
    .unwrap();
    let opened = bridge::verify_and_open_bytes(
        &json,
        &bundle_json,
        &recipients[0].try_to_bytes().unwrap(),
        &serde_json::to_string(&recipient).unwrap(),
        &destination(),
    )
    .unwrap();
    assert_eq!(opened, app.to_bytes().unwrap());
    let encryption_keys = serde_json::to_string(&vec![
        STANDARD.encode(recipients[0].public_key_bundle().try_as_bytes().unwrap()),
    ])
    .unwrap();
    let bridge_wire = bridge::sign_protected_bytes(
        &serde_json::to_string(&signer).unwrap(),
        &serde_json::to_string(&recipient).unwrap(),
        &destination(),
        "opaque-message",
        42,
        &TypeMap::latest().version.to_string(),
        &app.to_bytes().unwrap(),
        &sender.try_to_bytes().unwrap(),
        &encryption_keys,
    )
    .unwrap();
    assert_eq!(
        verify_and_open(&bridge_wire, &signer_keys, &recipients[0], None, None)
            .unwrap()
            .application
            .to_bytes()
            .unwrap(),
        opened
    );
    wire.into_frame(99).unwrap().to_bytes().unwrap();
}

#[test]
fn tampering_and_inner_outer_binding() {
    let sender = Keyring::generate();
    let recipient = Keyring::generate();
    let wire = sign_protected(
        principal("a", 1),
        principal("b", 2),
        destination(),
        "opaque".into(),
        12,
        application(),
        &sender,
        vec![recipient.public_key_bundle()],
    )
    .unwrap();
    let mut plaintext = wire.clone();
    plaintext.content = STANDARD.encode(application().to_bytes().unwrap());
    resign(&mut plaintext, &sender);
    assert!(
        verify_outer(
            &plaintext.to_json().unwrap(),
            &[sender.public_key_bundle()],
            None,
            None
        )
        .is_err()
    );
    for field in [
        "signer",
        "recipient",
        "destination",
        "message_id",
        "created_at",
        "type_map_version",
        "signature",
        "content",
    ] {
        let mut changed = wire.clone();
        match field {
            "signer" => changed.signer.authority = "different".into(),
            "recipient" => changed.recipient.authority = "different".into(),
            "destination" => changed.destination = format!("iota:v1:{}", "b".repeat(64)),
            "message_id" => changed.message_id = "changed".into(),
            "created_at" => changed.created_at += 1,
            "type_map_version" => changed.type_map_version = "99.0".into(),
            "signature" => changed.signature = STANDARD.encode([0; 64]),
            "content" => changed.content = STANDARD.encode([0; 64]),
            _ => unreachable!(),
        }
        assert!(
            verify_outer(
                &changed.to_json().unwrap(),
                &[sender.public_key_bundle()],
                None,
                None
            )
            .is_err(),
            "{field}"
        );
    }
    for field in ["message_id", "created_at", "signer", "recipient"] {
        let mut changed = wire.clone();
        match field {
            "message_id" => changed.message_id = "changed".into(),
            "created_at" => changed.created_at += 1,
            "signer" => changed.signer.user_id += 1,
            "recipient" => changed.recipient.user_id += 1,
            _ => unreachable!(),
        }
        resign(&mut changed, &sender);
        assert!(
            verify_and_open(
                &changed.to_json().unwrap(),
                &[sender.public_key_bundle()],
                &recipient,
                None,
                None
            )
            .is_err(),
            "{field}"
        );
    }
    for id in ["".to_owned(), "x".repeat(257)] {
        let mut changed = wire.clone();
        changed.message_id = id;
        resign(&mut changed, &sender);
        assert!(
            verify_outer(
                &changed.to_json().unwrap(),
                &[sender.public_key_bundle()],
                None,
                None
            )
            .is_err()
        );
    }
}

#[test]
fn deterministic_canonical_and_chat_vectors() {
    let a = principal("a", 10);
    let b = principal("a", 2);
    assert_eq!(canonical_chat_id(&a, &b), canonical_chat_id(&b, &a));
    assert_eq!(
        canonical_chat_participants(&a, &b),
        [
            r#"{"authority":"a","user_id":2}"#,
            r#"{"authority":"a","user_id":10}"#
        ]
    );
    assert_eq!(
        canonical_chat_id(&a, &b),
        "principal:v2:W3siYXV0aG9yaXR5IjoiYSIsInVzZXJfaWQiOjJ9LHsiYXV0aG9yaXR5IjoiYSIsInVzZXJfaWQiOjEwfV0"
    );
    assert_eq!(chat_secret_id("abc"), "chat:abc:main");
    let wire = RelayWire {
        version: 2,
        signer: a,
        recipient: b,
        destination: "n".into(),
        message_id: "i".into(),
        created_at: 3,
        type_map_version: "3.0".into(),
        content: String::new(),
        signature: String::new(),
    };
    let mut expected = SIGNING_DOMAIN.to_vec();
    expected.extend_from_slice(b"\0\0\0\x01a\0\0\0\0\0\0\0\x0a\0\0\0\x01a\0\0\0\0\0\0\0\x02\0\0\0\x01n\0\0\0\x01i\0\0\0\0\0\0\0\x03\0\0\0\x033.0\0\0\0\x02hi");
    assert_eq!(canonical_bytes(&wire, b"hi").unwrap(), expected);
    assert_eq!(derived_message_id("opaque"), derived_message_id("opaque"));
    assert_ne!(derived_message_id("opaque"), derived_message_id("other"));
}
