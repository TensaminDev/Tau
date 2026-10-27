use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use tau_relay_protocol::{ConversationPair, Principal, canonical_chat_id, chat_secret_id};

fn principal(key: char, user_id: u64) -> Principal {
    Principal::new(format!("omega-key:{}", key.to_string().repeat(64)), user_id).unwrap()
}

#[test]
fn equal_numbers_on_distinct_authorities_have_a_symmetric_namespace() {
    let a = principal('a', 42);
    let b = principal('b', 42);
    let pair = ConversationPair::new(a.clone(), b.clone()).unwrap();
    assert_eq!(pair, ConversationPair::new(b.clone(), a.clone()).unwrap());
    let chat = pair.chat_id().unwrap();
    assert_eq!(chat, canonical_chat_id(&b, &a));
    assert_eq!(ConversationPair::from_chat_id(&chat).unwrap(), pair);
    assert_eq!(chat_secret_id(&chat), format!("chat:{chat}:main"));
    assert_ne!(chat, canonical_chat_id(&a, &principal('c', 42)));
    assert!(pair.partner(&principal('c', 42)).is_err());
}

#[test]
fn principals_reject_unpinned_authorities_and_nonpersistent_ids() {
    for authority in [
        "",
        "omega:example.org",
        "iota:a",
        " example.org",
        "omega-key:abcd",
    ] {
        assert!(Principal::new(authority.into(), 42).is_err());
    }
    for authority in [
        format!("omega-key:{}", "A".repeat(64)),
        format!("omega-key:{} ", "a".repeat(64)),
    ] {
        assert!(Principal::new(authority, 42).is_err());
    }
    let authority = principal('a', 42).authority;
    for id in [0, i64::MAX as u64 + 1, u64::MAX] {
        assert!(Principal::new(authority.clone(), id).is_err());
        let json = format!(r#"{{"authority":"{authority}","user_id":{id}}}"#);
        assert!(serde_json::from_str::<Principal>(&json).is_err());
    }
    assert!(Principal::new(authority, i64::MAX as u64).is_ok());
    assert!(ConversationPair::new(principal('a', 1), principal('a', 1)).is_err());
}

#[test]
fn namespace_rejects_alternate_json_and_base64_encodings() {
    let a = principal('a', 42);
    let b = principal('b', 42);
    let chat = canonical_chat_id(&a, &b);
    for alternate in ["42:79".to_owned(), format!("{chat}="), format!(" {chat}")] {
        assert!(ConversationPair::from_chat_id(&alternate).is_err());
    }
    for json in [
        serde_json::to_string(&[&b, &a]).unwrap(),
        format!(
            r#"[{{"user_id":42,"authority":"{}"}},{{"authority":"{}","user_id":42}}]"#,
            a.authority, b.authority
        ),
        serde_json::to_string_pretty(&[&a, &b]).unwrap(),
        format!(
            r#"[{{"authority":"{}","authority":"{}","user_id":42}},{{"authority":"{}","user_id":42}}]"#,
            a.authority, a.authority, b.authority
        ),
        format!("{} trailing", serde_json::to_string(&[&a, &b]).unwrap()),
    ] {
        assert!(
            ConversationPair::from_chat_id(&format!("principal:{}", URL_SAFE_NO_PAD.encode(json)))
                .is_err()
        );
    }
}

#[test]
fn principal_objects_reject_duplicate_and_unknown_fields() {
    let authority = principal('a', 42).authority;
    for json in [
        format!(r#"{{"authority":"{authority}","user_id":42,"user_id":43}}"#),
        format!(r#"{{"authority":"{authority}","user_id":42,"home":"example.org"}}"#),
        format!(r#"{{"authority":"{authority}","user_id":42.0}}"#),
        format!(r#"{{"authority":"{authority}","user_id":"42"}}"#),
    ] {
        assert!(serde_json::from_str::<Principal>(&json).is_err());
    }
}
