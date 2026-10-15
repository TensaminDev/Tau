use crate::ProtocolValueError;
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::type_map::{DataTypeId, TypeMap};

pub trait CommunicationResponseExt {
    fn with_request_id(self, request: &CommunicationValue) -> Self;
}

impl CommunicationResponseExt for CommunicationValue {
    fn with_request_id(self, request: &CommunicationValue) -> Self {
        match request.id() {
            Some(id) => self.with_id(id),
            None => self.without_id(),
        }
    }
}

/// Routing a reply does not establish the request sender's authority.
pub fn error_response(
    request: &CommunicationValue,
    kind: CommunicationType,
    type_map: &TypeMap,
) -> CommunicationValue {
    let mut response =
        CommunicationValue::new_with_type_map(kind, type_map).with_request_id(request);
    if let Some(sender) = request.sender() {
        response = response.with_receiver(sender);
    }
    response
}

pub fn typed_container(
    type_map: &TypeMap,
    items: impl IntoIterator<Item = (DataType, DataValue)>,
) -> Result<DataValue, ProtocolValueError> {
    let fields = items
        .into_iter()
        .map(|(kind, value)| {
            type_map
                .data_id_enum(kind)
                .map(|id| (DataTypeId(id), value))
                .ok_or(ProtocolValueError::Invalid("unmapped data type"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DataValue::Container(fields))
}

/// Accept strings or integer representations. Other value kinds are rejected.
pub fn data_string(value: &CommunicationValue, kind: DataType) -> Option<String> {
    match value
        .payload()
        .get_field(DataTypeId(value.type_map()?.data_id_enum(kind)?))?
    {
        DataValue::Str(value) => Some(value.clone()),
        DataValue::SignedNumber(value) => Some(value.to_string()),
        DataValue::UnsignedNumber(value) => Some(value.to_string()),
        _ => None,
    }
}

/// Accept signed/unsigned integers or numeric strings, with checked conversion.
/// Missing values, invalid strings and overflow return None, never zero.
pub fn data_i64(value: &CommunicationValue, kind: DataType) -> Option<i64> {
    match value
        .payload()
        .get_field(DataTypeId(value.type_map()?.data_id_enum(kind)?))?
    {
        DataValue::SignedNumber(value) => i64::try_from(*value).ok(),
        DataValue::UnsignedNumber(value) => i64::try_from(*value).ok(),
        DataValue::Str(value) => value.parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_type_map_does_not_drop_fields() {
        let map = TypeMap::new(mtp::type_map::Version::new(u16::MAX, 0));
        assert_eq!(
            typed_container(&map, [(DataType::UserId, DataValue::SignedNumber(7))]),
            Err(ProtocolValueError::Invalid("unmapped data type"))
        );
    }

    #[test]
    fn replies_keep_explicit_type_map_and_optional_routing() {
        let map = TypeMap::new(mtp::type_map::Version::new(u16::MAX, 0));
        let request = CommunicationValue::new(CommunicationType::Ping)
            .without_id()
            .with_sender(7);
        let response = error_response(&request, CommunicationType::ErrorProtocol, &map);
        assert_eq!(response.type_map(), Some(&map));
        assert_eq!(response.id(), None);
        assert_eq!(response.receiver(), Some(7));
    }

    #[test]
    fn field_parsing_uses_frame_type_map_without_latest_fallback() {
        let mut frame = CommunicationValue::new(CommunicationType::Success)
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(7));
        frame.set_type_map(&TypeMap::new(mtp::type_map::Version::new(u16::MAX, 0)));
        assert_eq!(data_i64(&frame, DataType::UserId), None);
        assert_eq!(data_string(&frame, DataType::UserId), None);
    }

    #[test]
    fn numeric_fields_reject_invalid_data_and_overflow() {
        for value in [
            DataValue::UnsignedNumber(u128::MAX),
            DataValue::SignedNumber(i128::MAX),
            DataValue::Str("invalid".into()),
            DataValue::Bool(false),
        ] {
            let frame = CommunicationValue::new(CommunicationType::Success)
                .add_typed_default(DataType::UserId, value);
            assert_eq!(data_i64(&frame, DataType::UserId), None);
        }
        let frame = CommunicationValue::new(CommunicationType::Success)
            .add_typed_default(DataType::UserId, DataValue::Str("-7".into()));
        assert_eq!(data_i64(&frame, DataType::UserId), Some(-7));
        assert_eq!(
            data_i64(
                &CommunicationValue::new(CommunicationType::Success),
                DataType::UserId
            ),
            None
        );
    }
}
