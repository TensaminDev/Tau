use mtp::codec::{CommunicationValue, DataValue};
use mtp::type_map::DataTypeId;
use thiserror::Error;

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum MtpFieldError {
    #[error("message is missing an MTP id")]
    MissingId,
    #[error("message is missing an MTP sender")]
    MissingSender,
    #[error("message is missing an MTP receiver")]
    MissingReceiver,
}

pub trait RequiredCommunicationFields {
    fn require_id(&self) -> Result<u32, MtpFieldError>;
    fn require_sender(&self) -> Result<u64, MtpFieldError>;
    fn require_receiver(&self) -> Result<u64, MtpFieldError>;
}

impl RequiredCommunicationFields for CommunicationValue {
    fn require_id(&self) -> Result<u32, MtpFieldError> {
        self.id().ok_or(MtpFieldError::MissingId)
    }

    fn require_sender(&self) -> Result<u64, MtpFieldError> {
        self.sender().ok_or(MtpFieldError::MissingSender)
    }

    fn require_receiver(&self) -> Result<u64, MtpFieldError> {
        self.receiver().ok_or(MtpFieldError::MissingReceiver)
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum ProtocolValueError {
    #[error("missing {0}")]
    Missing(&'static str),
    #[error("invalid {0}")]
    Invalid(&'static str),
    #[error("{0} is outside the supported range")]
    OutOfRange(&'static str),
}

/// Read a required numeric field and reject zero and negative values.
pub fn positive_data_i64(
    value: &CommunicationValue,
    data_type: mtp::codec::DataType,
    field: &'static str,
) -> Result<i64, ProtocolValueError> {
    let raw = value
        .type_map()
        .and_then(|map| map.data_id_enum(data_type))
        .and_then(|id| value.payload().get_field(DataTypeId(id)))
        .as_number()
        .ok_or(ProtocolValueError::Missing(field))?;
    let id = i64::try_from(raw).map_err(|_| ProtocolValueError::OutOfRange(field))?;
    if id <= 0 {
        return Err(ProtocolValueError::Invalid(field));
    }
    Ok(id)
}

#[allow(
    clippy::wrong_self_convention,
    reason = "mirror DataValue accessors on optional borrowed values"
)]
pub trait OptionalDataValueExt<'a> {
    fn as_bool(self) -> Option<bool>;
    fn as_str(self) -> Option<&'a str>;
    fn as_string(self) -> Option<String>;
    fn as_number(self) -> Option<i128>;
    fn as_signed_number(self) -> Option<i128>;
    fn as_bytes(self) -> Option<Vec<u8>>;
    fn as_array(self) -> Option<Vec<DataValue>>;
    fn as_container(self) -> Option<Vec<(DataTypeId, DataValue)>>;
}

impl<'a> OptionalDataValueExt<'a> for Option<&'a DataValue> {
    fn as_bool(self) -> Option<bool> {
        self.and_then(DataValue::as_bool)
    }

    fn as_str(self) -> Option<&'a str> {
        self.and_then(DataValue::as_str)
    }

    fn as_string(self) -> Option<String> {
        self.and_then(DataValue::as_string)
    }

    fn as_number(self) -> Option<i128> {
        self.and_then(DataValue::as_number)
    }

    fn as_signed_number(self) -> Option<i128> {
        self.and_then(DataValue::as_signed_number)
    }

    fn as_bytes(self) -> Option<Vec<u8>> {
        self.and_then(DataValue::as_bytes)
    }

    fn as_array(self) -> Option<Vec<DataValue>> {
        self.and_then(DataValue::as_array)
    }

    fn as_container(self) -> Option<Vec<(DataTypeId, DataValue)>> {
        self.and_then(DataValue::as_container)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MtpFieldError, OptionalDataValueExt, ProtocolValueError, RequiredCommunicationFields,
        positive_data_i64,
    };
    use mtp::codec::{CommunicationType, CommunicationValue, DataType};

    #[test]
    fn missing_routing_fields_are_reported_instead_of_defaulted() {
        let message = CommunicationValue::new(CommunicationType::Success).without_id();

        assert_eq!(message.require_id(), Err(MtpFieldError::MissingId));
        assert_eq!(message.require_sender(), Err(MtpFieldError::MissingSender));
        assert_eq!(
            message.require_receiver(),
            Err(MtpFieldError::MissingReceiver)
        );
    }

    #[test]
    fn present_routing_fields_are_returned_unchanged() {
        let message = CommunicationValue::new(CommunicationType::Success)
            .with_id(7)
            .with_sender(8)
            .with_receiver(9);

        assert_eq!(message.require_id(), Ok(7));
        assert_eq!(message.require_sender(), Ok(8));
        assert_eq!(message.require_receiver(), Ok(9));
    }

    #[test]
    fn positive_numbers_are_accepted_and_zero_is_rejected() {
        let positive = CommunicationValue::new(CommunicationType::Success)
            .add_typed_default(DataType::UserId, mtp::codec::DataValue::UnsignedNumber(7));
        let zero = CommunicationValue::new(CommunicationType::Success)
            .add_typed_default(DataType::UserId, mtp::codec::DataValue::UnsignedNumber(0));
        let missing = CommunicationValue::new(CommunicationType::Success);

        assert_eq!(positive_data_i64(&positive, DataType::UserId, "id"), Ok(7));
        assert_eq!(
            positive_data_i64(&zero, DataType::UserId, "id"),
            Err(ProtocolValueError::Invalid("id"))
        );
        assert_eq!(
            positive_data_i64(&missing, DataType::UserId, "id"),
            Err(ProtocolValueError::Missing("id"))
        );
    }

    #[test]
    fn optional_values_expose_their_contents() {
        let message = CommunicationValue::new(CommunicationType::Success).add_typed_default(
            DataType::ErrorType,
            mtp::codec::DataValue::Str("gone".into()),
        );

        assert_eq!(message.get_data(DataType::ErrorType).as_str(), Some("gone"));
        assert_eq!(
            message.get_data(DataType::ErrorType).as_string(),
            Some("gone".to_string())
        );
        assert_eq!(message.get_data(DataType::UserId).as_number(), None);
    }
}
