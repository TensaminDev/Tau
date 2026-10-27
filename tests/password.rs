use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue, TypeMap};
use tau::password::Failure;

#[test]
fn password_failures_have_one_machine_readable_class_and_retry_policy() {
    let map = TypeMap::new(mtp::type_map::Version(1, 0));
    for failure in [
        Failure::InvalidRequest,
        Failure::Unauthorized,
        Failure::Expired,
        Failure::Cancelled,
        Failure::Conflict,
        Failure::DependencyUnavailable,
        Failure::RateLimited,
        Failure::UnknownOutcome,
    ] {
        let frame = CommunicationValue::new_with_type_map(failure.message_type(), &map)
            .with_id(42)
            .with_payload(failure.payload(&map).unwrap());
        assert_eq!(Failure::from_frame(&frame).unwrap(), failure);
        assert_eq!(frame.id(), Some(42));
        let mut duplicate = frame.payload().clone();
        duplicate.container_entries_mut().unwrap().push((
            DataType::ErrorType.try_to_id(&map).unwrap(),
            DataValue::Str(failure.to_string()),
        ));
        assert!(Failure::from_frame(&frame.clone().with_payload(duplicate)).is_err());
        assert!(
            Failure::from_frame(
                &CommunicationValue::new_with_type_map(CommunicationType::Success, &map)
                    .with_payload(frame.payload().clone())
            )
            .is_err()
        );
        let bad_json = serde_json::to_vec(
            &serde_json::json!({"code":failure,"retryable":!failure.retryable()}),
        )
        .unwrap();
        assert!(
            Failure::from_frame(&frame.with_data(DataType::Json, DataValue::Bytes(bad_json)))
                .is_err()
        );
    }
}
