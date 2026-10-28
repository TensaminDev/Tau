//! Account synchronization contract. A page write is not an acknowledgement.
use crate::{Principal, dictionary_fingerprint};
use serde::{Deserialize, Serialize};

pub const SCHEMA: &str = "tensamin-account-sync:v1";
pub const PAGE_LIMIT: usize = 128;
pub const PAGE_BYTES: usize = 1024 * 1024;

/// Dictionary 1.1 only adds file operations. The account-sync JSON schema and
/// all pre-existing numeric assignments are unchanged.
pub fn dictionaries_compatible(first: &str, second: &str) -> bool {
    let known = |value: &str| {
        ["1.0", "1.1"]
            .iter()
            .any(|version| dictionary_fingerprint(version).is_ok_and(|hash| hash == value))
    };
    known(first) && known(second)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub principal: Principal,
    pub device_id: String,
    pub authorization_generation: i64,
    pub schema: String,
    pub dictionary: String,
}

impl Scope {
    pub fn validate(&self) -> bool {
        self.principal.validate().is_ok()
            && !self.device_id.is_empty()
            && self.device_id.len() <= 128
            && self
                .device_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
            && self.authorization_generation >= 0
            && self.schema == SCHEMA
            && ["1.0", "1.1"].iter().any(|version| {
                dictionary_fingerprint(version).is_ok_and(|value| value == self.dictionary)
            })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cursor {
    pub scope: Scope,
    pub sequence: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Snapshot {
        scope: Scope,
        page: Option<PageToken>,
        limit: usize,
    },
    Delta {
        after: Cursor,
        page: Option<PageToken>,
        limit: usize,
    },
    Acknowledge {
        cursor: Cursor,
        page_id: String,
    },
}

impl Request {
    pub fn scope(&self) -> &Scope {
        match self {
            Self::Snapshot { scope, .. } => scope,
            Self::Delta { after, .. } => &after.scope,
            Self::Acknowledge { cursor, .. } => &cursor.scope,
        }
    }

    pub fn validate(&self) -> bool {
        self.scope().validate()
            && match self {
                Self::Snapshot { page, limit, .. } => valid_page(page, *limit),
                Self::Delta { after, page, limit } => {
                    after.sequence >= 0 && valid_page(page, *limit)
                }
                Self::Acknowledge { cursor, page_id } => cursor.sequence >= 0 && valid_id(page_id),
            }
    }
}

fn valid_id(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}
fn valid_page(page: &Option<PageToken>, limit: usize) -> bool {
    (1..=PAGE_LIMIT).contains(&limit) && page.as_ref().is_none_or(PageToken::validate)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageToken {
    pub id: String,
    pub offset: i64,
}

impl PageToken {
    pub fn validate(&self) -> bool {
        valid_id(&self.id) && self.offset >= 0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub entity: Entity,
    pub key: String,
    pub value: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub sequence: i64,
    pub event_id: String,
    pub entity: Entity,
    pub key: String,
    pub operation: EventAction,
    pub record: Option<Record>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Entity {
    Message,
    Contact,
    Setting,
    UserBlob,
    UserAsset,
    ChatSecret,
    BlockedUser,
    ReceiptPolicy,
    MessageStoragePolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventAction {
    Upsert,
    Delete,
}

impl TryFrom<&str> for Entity {
    type Error = SyncError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "message" => Ok(Self::Message),
            "contact" => Ok(Self::Contact),
            "setting" => Ok(Self::Setting),
            "user_blob" => Ok(Self::UserBlob),
            "user_asset" => Ok(Self::UserAsset),
            "chat_secret" => Ok(Self::ChatSecret),
            "blocked_user" => Ok(Self::BlockedUser),
            "receipt_policy" => Ok(Self::ReceiptPolicy),
            "message_storage_policy" => Ok(Self::MessageStoragePolicy),
            _ => Err(SyncError::InvalidRequest),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Snapshot {
        scope: Scope,
        head: i64,
        floor: i64,
        page_id: String,
        next: Option<PageToken>,
        records: Vec<Record>,
    },
    Delta {
        scope: Scope,
        head: i64,
        floor: i64,
        page_id: String,
        next: Option<PageToken>,
        events: Vec<Event>,
    },
    Acknowledged {
        cursor: Cursor,
    },
    Unavailable {
        error: SyncError,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncError {
    SnapshotRequired,
    IdentityChanged,
    Retryable,
    Unauthorized,
    InvalidRequest,
    Capacity,
}
