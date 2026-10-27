//! Exactly one JSON payload, always under the selected application dictionary.
pub use crate::relay_protocol::sync::*;
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};

pub fn encode_request(
    request: &Request,
    map: &mtp::codec::TypeMap,
    correlation_id: u32,
) -> Result<CommunicationValue, SyncError> {
    if !request.validate()
        || map.fingerprint_hex().as_deref() != Some(request.scope().dictionary.as_str())
        || CommunicationType::AccountStateRequest
            .try_to_id(map)
            .is_none()
        || DataType::Json.try_to_id(map).is_none()
    {
        return Err(SyncError::InvalidRequest);
    }
    let bytes = serde_json::to_vec(request).map_err(|_| SyncError::InvalidRequest)?;
    if bytes.len() > 4096 {
        return Err(SyncError::InvalidRequest);
    }
    Ok(
        CommunicationValue::new_with_type_map(CommunicationType::AccountStateRequest, map)
            .with_id(correlation_id)
            .add_typed_default(DataType::Json, DataValue::Bytes(bytes)),
    )
}

pub fn decode_request(frame: &CommunicationValue) -> Result<Request, SyncError> {
    let map = frame.type_map().ok_or(SyncError::InvalidRequest)?;
    if map.version.to_string() != "1.0"
        || map.fingerprint().is_none()
        || !frame.is_type(CommunicationType::AccountStateRequest)
    {
        return Err(SyncError::InvalidRequest);
    }
    let fields = frame
        .payload()
        .container_entries()
        .ok_or(SyncError::InvalidRequest)?;
    let [(id, DataValue::Bytes(bytes))] = fields else {
        return Err(SyncError::InvalidRequest);
    };
    if Some(*id) != DataType::Json.try_to_id(map) || bytes.len() > 4096 {
        return Err(SyncError::InvalidRequest);
    }
    let request: Request = serde_json::from_slice(bytes).map_err(|_| SyncError::InvalidRequest)?;
    if !request.validate() {
        return Err(SyncError::InvalidRequest);
    }
    Ok(request)
}

pub fn encode_response(
    request: &CommunicationValue,
    response: &Response,
) -> Result<CommunicationValue, SyncError> {
    use crate::CommunicationResponseExt;
    let map = request.type_map().ok_or(SyncError::InvalidRequest)?;
    let bytes = serde_json::to_vec(response).map_err(|_| SyncError::Retryable)?;
    if bytes.len() > PAGE_BYTES {
        return Err(SyncError::Capacity);
    }
    Ok(
        crate::error_response(request, CommunicationType::AccountStateSnapshot, map)
            .with_request_id(request)
            .add_typed_default(DataType::Json, DataValue::Bytes(bytes)),
    )
}

pub fn decode_response(
    frame: &CommunicationValue,
    request: &CommunicationValue,
) -> Result<Response, SyncError> {
    let expected = decode_request(request)?;
    if frame.id() != request.id()
        || frame.type_map() != request.type_map()
        || !frame.is_type(CommunicationType::AccountStateSnapshot)
    {
        return Err(SyncError::InvalidRequest);
    }
    let map = frame.type_map().ok_or(SyncError::InvalidRequest)?;
    let fields = frame
        .payload()
        .container_entries()
        .ok_or(SyncError::InvalidRequest)?;
    let [(id, DataValue::Bytes(bytes))] = fields else {
        return Err(SyncError::InvalidRequest);
    };
    if Some(*id) != DataType::Json.try_to_id(map) || bytes.len() > PAGE_BYTES {
        return Err(SyncError::InvalidRequest);
    }
    let response: Response =
        serde_json::from_slice(bytes).map_err(|_| SyncError::InvalidRequest)?;
    let valid = match (&response, &expected) {
        (Response::Unavailable { .. }, _) => true,
        (
            Response::Snapshot {
                scope,
                head,
                floor,
                records,
                next,
                page_id,
            },
            Request::Snapshot {
                scope: requested,
                limit,
                page,
            },
        ) => {
            scope == requested
                && *head >= *floor
                && *floor >= 0
                && records.len() <= *limit
                && page_matches(page_id, next, page, records.len())
        }
        (
            Response::Delta {
                scope,
                head,
                floor,
                events,
                next,
                page_id,
            },
            Request::Delta { after, limit, page },
        ) => {
            scope == &after.scope
                && *head >= after.sequence
                && after.sequence >= *floor
                && *floor >= 0
                && events.len() <= *limit
                && events
                    .iter()
                    .all(|event| event.sequence > after.sequence && event.sequence <= *head)
                && events
                    .windows(2)
                    .all(|events| events[0].sequence < events[1].sequence)
                && page_matches(page_id, next, page, events.len())
        }
        (
            Response::Acknowledged { cursor },
            Request::Acknowledge {
                cursor: requested, ..
            },
        ) => cursor == requested,
        _ => false,
    };
    if !valid {
        return Err(SyncError::InvalidRequest);
    }
    Ok(response)
}

fn page_matches(
    id: &str,
    next: &Option<PageToken>,
    requested: &Option<PageToken>,
    count: usize,
) -> bool {
    let offset = requested.as_ref().map_or(0, |page| page.offset);
    let page = PageToken {
        id: id.into(),
        offset,
    };
    if !page.validate()
        || requested
            .as_ref()
            .is_some_and(|requested| requested.id != id)
    {
        return false;
    }
    let Some(end) = offset.checked_add(count as i64) else {
        return false;
    };
    next.as_ref()
        .is_none_or(|next| next.id == id && count > 0 && next.offset == end)
}
