use mtp::codec::{CommunicationType, DataType, DataValue, TypeMap};
use tau::chat_secret::{ReadRequest, ReadUnavailable, SecretEpoch};
use tau::relay_protocol::{ConversationPair, Principal, chat_secret_id};

fn request() -> ReadRequest {
    let owner = Principal::new(format!("omega-key:{}", "a".repeat(64)), 42).unwrap();
    let peer = Principal::new(format!("omega-key:{}", "b".repeat(64)), 42).unwrap();
    let pair = ConversationPair::new(owner.clone(), peer).unwrap();
    ReadRequest {
        secret_id: chat_secret_id(&pair.chat_id().unwrap()),
        owner,
        pair,
        epoch: None,
    }
}

#[test]
fn latest_and_named_epoch_reads_round_trip_with_canonical_scope() {
    let map = TypeMap::new(mtp::type_map::Version(1, 0));
    for epoch in [None, Some(SecretEpoch::try_from(3).unwrap())] {
        let mut request = request();
        request.epoch = epoch;
        let frame = request.to_frame(&map, 42).unwrap();
        assert_eq!(ReadRequest::from_frame(&frame).unwrap(), request);
        assert_eq!(frame.type_map(), Some(&map));
    }
}

#[test]
fn read_decoders_reject_aliases_extra_fields_and_invalid_epochs() {
    let map = TypeMap::new(mtp::type_map::Version(1, 0));
    let frame = request().to_frame(&map, 42).unwrap();
    for invalid in [
        frame
            .clone()
            .with_data(DataType::UserId, DataValue::UnsignedNumber(42)),
        frame
            .clone()
            .with_data(DataType::UserId, DataValue::Str("42".into())),
        frame
            .clone()
            .with_data(DataType::ChatId, DataValue::Str("42:79".into())),
        frame
            .clone()
            .with_data(DataType::SecretId, DataValue::Str("chat:42:79:main".into())),
        frame
            .clone()
            .with_data(DataType::VersionNumber, DataValue::SignedNumber(0)),
        frame.clone().with_data(
            DataType::VersionNumber,
            DataValue::UnsignedNumber(u128::MAX),
        ),
        frame
            .clone()
            .with_data(DataType::VersionNumber, DataValue::Str("1".into())),
        frame
            .clone()
            .add_typed_default(DataType::Principal, DataValue::Str("extra".into())),
    ] {
        assert!(ReadRequest::from_frame(&invalid).is_err());
    }
    let mut fields = frame.payload().clone();
    let duplicate = fields.container_entries().unwrap()[0].clone();
    fields.container_entries_mut().unwrap().push(duplicate);
    assert!(ReadRequest::from_frame(&frame.with_payload(fields)).is_err());
    assert!(
        request()
            .to_frame(&TypeMap::new(mtp::type_map::Version(65535, 0)), 42)
            .is_err()
    );
}

#[test]
fn unavailable_states_are_exact_correlated_outcomes_not_generic_success() {
    let map = TypeMap::new(mtp::type_map::Version(1, 0));
    let request = request().to_frame(&map, 42).unwrap();
    for state in [
        ReadUnavailable::NoSuchConversation,
        ReadUnavailable::Pending,
        ReadUnavailable::EpochUnavailable,
        ReadUnavailable::AcceptedButEnvelopeUnavailable,
        ReadUnavailable::Unauthorized,
        ReadUnavailable::Conflict,
        ReadUnavailable::RetryableDependency,
    ] {
        let reply = state.to_frame(&request).unwrap();
        assert_eq!(
            ReadUnavailable::from_frame(&reply, &request).unwrap(),
            state
        );
        assert!(!reply.is_type(CommunicationType::Success));
        assert!(ReadUnavailable::from_frame(&reply.clone().with_id(43), &request).is_err());
        assert!(
            ReadUnavailable::from_frame(
                &reply.with_data(DataType::ErrorType, DataValue::Str("other".into())),
                &request
            )
            .is_err()
        );
    }
    assert!(ReadUnavailable::Pending.retryable());
    assert!(!ReadUnavailable::NoSuchConversation.retryable());
}
