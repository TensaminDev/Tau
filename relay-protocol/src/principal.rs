use crate::Error;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

/// A pinned key identity, never a hostname, routing hint or local database ID.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "PrincipalFields")]
pub struct Principal {
    pub authority: String,
    pub user_id: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalFields {
    authority: String,
    user_id: u64,
}

impl TryFrom<PrincipalFields> for Principal {
    type Error = Error;

    fn try_from(fields: PrincipalFields) -> Result<Self, Error> {
        Self::new(fields.authority, fields.user_id)
    }
}

impl Principal {
    pub fn new(authority: String, user_id: u64) -> Result<Self, Error> {
        let principal = Self { authority, user_id };
        principal.validate()?;
        Ok(principal)
    }

    pub fn validate(&self) -> Result<(), Error> {
        Self::validate_authority(&self.authority)?;
        if self.user_id == 0 || self.user_id > i64::MAX as u64 {
            return Err(Error::Invalid("principal user ID"));
        }
        Ok(())
    }

    pub fn validate_authority(authority: &str) -> Result<(), Error> {
        let fingerprint = authority
            .strip_prefix("omega-key:")
            .or_else(|| authority.strip_prefix("authority:iota:v1:"))
            .ok_or(Error::Invalid("pinned authority ID"))?;
        if fingerprint.len() != 64
            || !fingerprint
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Invalid("canonical authority fingerprint"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "PairFields")]
pub struct ConversationPair {
    pub first: Principal,
    pub second: Principal,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairFields {
    first: Principal,
    second: Principal,
}

impl TryFrom<PairFields> for ConversationPair {
    type Error = Error;

    fn try_from(fields: PairFields) -> Result<Self, Error> {
        let pair = Self {
            first: fields.first,
            second: fields.second,
        };
        pair.validate()?;
        Ok(pair)
    }
}

impl ConversationPair {
    pub fn new(a: Principal, b: Principal) -> Result<Self, Error> {
        let (first, second) = if a < b { (a, b) } else { (b, a) };
        let pair = Self { first, second };
        pair.validate()?;
        Ok(pair)
    }

    pub fn validate(&self) -> Result<(), Error> {
        self.first.validate()?;
        self.second.validate()?;
        if self.first >= self.second {
            return Err(Error::Invalid("distinct sorted principals"));
        }
        Ok(())
    }

    pub fn partner(&self, owner: &Principal) -> Result<&Principal, Error> {
        self.validate()?;
        if owner == &self.first {
            Ok(&self.second)
        } else if owner == &self.second {
            Ok(&self.first)
        } else {
            Err(Error::Invalid("conversation owner"))
        }
    }

    pub fn chat_id(&self) -> Result<String, Error> {
        self.validate()?;
        Ok(encode_chat_id([&self.first, &self.second]))
    }

    /// Decode then re-encode to reject reordered objects, padding and JSON aliases.
    pub fn from_chat_id(chat_id: &str) -> Result<Self, Error> {
        if chat_id.len() > 1024 {
            return Err(Error::Invalid("chat ID length"));
        }
        let encoded = chat_id
            .strip_prefix("principal:")
            .ok_or(Error::Invalid("chat ID"))?;
        let bytes = URL_SAFE_NO_PAD.decode(encoded)?;
        let [first, second]: [Principal; 2] = serde_json::from_slice(&bytes)?;
        let pair = Self::new(first, second)?;
        if pair.chat_id()? != chat_id {
            return Err(Error::Invalid("noncanonical chat ID"));
        }
        Ok(pair)
    }
}

pub(super) fn encode_chat_id(pair: [&Principal; 2]) -> String {
    format!(
        "principal:{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&pair).expect("principal JSON"))
    )
}
