use super::*;
use mtp::codec::{DecodeLimits, EncodeLimits, ProtectedLimits};

/// One policy for native and browser relay boundaries. Sizes are bytes, not characters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayProtocolLimits {
    pub max_wire_bytes: usize,
    pub max_protected_bytes: usize,
    pub max_application_bytes: usize,
    pub max_authority_bytes: usize,
    pub max_message_id_bytes: usize,
    pub max_type_map_version_bytes: usize,
    pub max_destination_bytes: usize,
    pub max_signer_keys: usize,
    pub max_recipient_keys: usize,
    pub max_depth: usize,
    /// MTP value nodes; JSON tokens including object keys count toward the same bound.
    pub max_fields: usize,
    pub max_allocated_bytes: usize,
}

impl Default for RelayProtocolLimits {
    fn default() -> Self {
        Self {
            max_wire_bytes: 24 * 1024 * 1024,
            max_protected_bytes: 16 * 1024 * 1024,
            max_application_bytes: 16 * 1024 * 1024,
            max_authority_bytes: 1024,
            max_message_id_bytes: 256,
            max_type_map_version_bytes: 32,
            max_destination_bytes: 72,
            max_signer_keys: 8,
            max_recipient_keys: mtp::crypto::MAX_RECIPIENTS,
            max_depth: 64,
            max_fields: 65_536,
            max_allocated_bytes: 64 * 1024 * 1024,
        }
    }
}

impl RelayProtocolLimits {
    pub(crate) fn decode(self, bytes: usize) -> DecodeLimits {
        DecodeLimits {
            max_depth: self.max_depth,
            max_values: self.max_fields,
            max_blob_size: bytes,
            max_recipients: self.max_recipient_keys.min(mtp::crypto::MAX_RECIPIENTS),
            max_allocated_bytes: self.max_allocated_bytes,
        }
    }

    pub(crate) fn encode(self, bytes: usize) -> EncodeLimits {
        EncodeLimits {
            max_depth: self.max_depth,
            max_values: self.max_fields,
            max_output_size: bytes,
        }
    }

    pub(crate) fn protected(self) -> ProtectedLimits {
        ProtectedLimits {
            max_metadata_encoded_bytes: self.max_protected_bytes,
            max_signer_key_history: self.max_signer_keys,
            max_decryption_key_history: 1,
        }
    }
}

pub(crate) fn bound(field: &'static str, actual: usize, max: usize) -> Result<(), Error> {
    if actual > max {
        return Err(Error::Limit { field, actual, max });
    }
    Ok(())
}

pub(crate) fn base64_len(bytes: usize) -> usize {
    bytes.div_ceil(3).saturating_mul(4)
}

pub(crate) fn decode_base64(
    value: &str,
    field: &'static str,
    max: usize,
) -> Result<Vec<u8>, Error> {
    validate_base64(value, field, max)?;
    Ok(STANDARD.decode(value)?)
}

pub(crate) fn validate_base64(
    value: &str,
    field: &'static str,
    max: usize,
) -> Result<usize, Error> {
    bound(field, value.len(), base64_len(max))?;
    // Account for padding before allocating the decoder output.
    let padding = value
        .as_bytes()
        .iter()
        .rev()
        .take_while(|&&b| b == b'=')
        .count();
    let decoded_len = (value.len() / 4).saturating_mul(3).saturating_sub(padding);
    bound(field, decoded_len, max)?;
    // Validate in fixed-size chunks without allocating decoded content.
    let mut output = [0u8; 768];
    for (index, chunk) in value.as_bytes().chunks(1024).enumerate() {
        if (index + 1) * 1024 < value.len() && chunk.contains(&b'=') {
            return Err(Error::Invalid("base64 padding"));
        }
        STANDARD
            .decode_slice(chunk, &mut output)
            .map_err(|_| Error::Invalid("base64 encoding"))?;
    }
    Ok(decoded_len)
}

/// Allocation-free preflight. Serde still validates the JSON grammar afterward.
/// The optional string policy is used for key arrays before Vec/String deserialization.
pub(crate) fn preflight_json(
    json: &[u8],
    max_bytes: usize,
    limits: &RelayProtocolLimits,
    strings: Option<(usize, usize)>,
) -> Result<(), Error> {
    bound("JSON bytes", json.len(), max_bytes)?;
    let mut depth = 0usize;
    let mut fields = 0usize;
    let mut string_count = 0usize;
    let mut i = 0;
    while i < json.len() {
        match json[i] {
            b'"' => {
                fields = fields.saturating_add(1);
                string_count = string_count.saturating_add(1);
                let start = i + 1;
                i += 1;
                while i < json.len() && json[i] != b'"' {
                    if json[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                if let Some((max_count, max_string_bytes)) = strings {
                    bound("key-list count", string_count, max_count)?;
                    bound(
                        "key JSON string bytes",
                        i - start,
                        max_string_bytes.saturating_mul(6),
                    )?;
                }
            }
            b'[' | b'{' => {
                depth = depth.saturating_add(1);
                fields = fields.saturating_add(1);
                bound("JSON depth", depth, limits.max_depth)?;
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            b',' | b':' | b' ' | b'\t' | b'\r' | b'\n' => {}
            _ => {
                fields = fields.saturating_add(1);
                while i + 1 < json.len()
                    && !matches!(
                        json[i + 1],
                        b',' | b']' | b'}' | b' ' | b'\t' | b'\r' | b'\n'
                    )
                {
                    i += 1;
                }
            }
        }
        bound("JSON fields", fields, limits.max_fields)?;
        i += 1;
    }
    Ok(())
}

// Count serialized bytes without allocating the output first.
pub(crate) fn json_bytes<T: Serialize>(value: &T, max: usize) -> Result<Vec<u8>, Error> {
    json_size(value, max)?;
    Ok(serde_json::to_vec(value)?)
}

pub(crate) fn json_size<T: Serialize>(value: &T, max: usize) -> Result<(), Error> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Counter(0);
    serde_json::to_writer(&mut count, value)?;
    bound("JSON bytes", count.0, max)?;
    Ok(())
}
