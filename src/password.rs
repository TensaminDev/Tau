//! Password RPC failures. Transport failure is not a remote mutation outcome.
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue, TypeMap};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    #[error("invalid_request")]
    InvalidRequest,
    #[error("unauthorized")]
    Unauthorized,
    #[error("expired")]
    Expired,
    #[error("cancelled")]
    Cancelled,
    #[error("conflict")]
    Conflict,
    #[error("dependency_unavailable")]
    DependencyUnavailable,
    #[error("rate_limited")]
    RateLimited,
    #[error("unknown_outcome")]
    UnknownOutcome,
}

impl Failure {
    pub fn retryable(self) -> bool {
        matches!(
            self,
            Self::DependencyUnavailable | Self::RateLimited | Self::UnknownOutcome
        )
    }

    pub fn message_type(self) -> CommunicationType {
        match self {
            Self::Unauthorized => CommunicationType::ErrorNotAuthenticated,
            Self::DependencyUnavailable | Self::RateLimited | Self::UnknownOutcome => {
                CommunicationType::ErrorInternal
            }
            _ => CommunicationType::ErrorInvalidData,
        }
    }

    pub fn payload(self, map: &TypeMap) -> Result<DataValue, &'static str> {
        let bytes = serde_json::to_vec(&Fields {
            code: self,
            retryable: self.retryable(),
        })
        .map_err(|_| "password failure encoding")?;
        crate::typed_container(
            map,
            vec![
                (DataType::ErrorType, DataValue::Str(self.to_string())),
                (DataType::Json, DataValue::Bytes(bytes)),
            ],
        )
        .map_err(|_| "password failure dictionary")
    }

    pub fn from_frame(frame: &CommunicationValue) -> Result<Self, &'static str> {
        let map = frame
            .type_map()
            .ok_or("missing password failure dictionary")?;
        let fields = frame
            .payload()
            .container_entries()
            .ok_or("password failure fields")?;
        if fields.len() != 2 {
            return Err("password failure field count");
        }
        let code_id = DataType::ErrorType
            .try_to_id(map)
            .ok_or("password failure dictionary")?;
        let json_id = DataType::Json
            .try_to_id(map)
            .ok_or("password failure dictionary")?;
        let mut code = None;
        let mut json = None;
        for (id, value) in fields {
            if *id == code_id && code.is_none() {
                code = value.as_str();
            } else if *id == json_id && json.is_none() {
                json = value.as_bytes_slice();
            } else {
                return Err("password failure duplicate or unknown field");
            }
        }
        let bytes = json
            .filter(|bytes| bytes.len() <= 1024)
            .ok_or("password failure JSON")?;
        let failure: Fields = serde_json::from_slice(bytes).map_err(|_| "password failure JSON")?;
        if code != Some(failure.code.to_string().as_str())
            || failure.retryable != failure.code.retryable()
            || !frame.is_type(failure.code.message_type())
        {
            return Err("password failure mismatch");
        }
        Ok(failure.code)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fields {
    code: Failure,
    retryable: bool,
}

// Input codec helpers may describe malformed fields with strings. Never expose
// those descriptions over the wire. Dependency failures need an explicit class.
impl From<String> for Failure {
    fn from(_: String) -> Self {
        Self::InvalidRequest
    }
}

impl From<&'static str> for Failure {
    fn from(_: &'static str) -> Self {
        Self::InvalidRequest
    }
}
