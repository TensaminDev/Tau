//! Application effects prepared from an authenticated relay. These values do
//! not establish acceptance until the backend's fenced transaction commits.
use mtp::codec::CommunicationValue;
use serde::{Deserialize, Serialize};

impl ApplicationOperation {
    /// Check the signed application payload before reading any security fields.
    /// Transport correlation and authenticated identity live outside this payload.
    pub fn validate_frame_shape(frame: &CommunicationValue) -> Result<(), crate::Error> {
        let map = frame
            .type_map()
            .ok_or(crate::Error::Invalid("application dictionary"))?;
        if !matches!(map.version.to_string().as_str(), "1.0" | "1.1")
            || map.fingerprint_hex().as_deref()
                != Some(crate::dictionary_fingerprint(&map.version.to_string())?.as_str())
        {
            return Err(crate::Error::Invalid("application dictionary"));
        }
        let allowed: &[&str] = match map.communication_type_name(frame.get_type().0) {
            Some("MessageSend") => &["Content", "SendTime", "Height", "VersionNumber", "ReplyId"],
            Some("MessageEdit") => &["Content", "SendTime", "VersionNumber"],
            Some("MessageReactionAdd" | "MessageReactionRemove") => &["Reaction", "SendTime"],
            Some("MessageDelete" | "MessageDeleteLive") => &["SendTime"],
            Some("MessageState") => &["ChatPartnerId", "MessageState", "RelayMessageId", "EventAt"],
            Some("SetChatSecret") => &["SecretId", "VersionNumber", "WrappingScheme", "Recipients"],
            Some("AddConversation") => &["ChatPartnerId", "ChatPartnerName"],
            Some("FileShareOffered" | "FileShareRevoked") => &["Json"],
            _ => return Err(crate::Error::Invalid("application operation")),
        };
        let fields = frame
            .payload()
            .container_entries()
            .ok_or(crate::Error::Invalid("application fields"))?;
        let mut seen = std::collections::BTreeSet::new();
        for (id, _) in fields {
            if !seen.insert(id.0)
                || !allowed
                    .iter()
                    .chain(["SenderId", "ReceiverId", "ChatId"].iter())
                    .any(|name| map.data_type_name(id.0) == Some(*name))
            {
                return Err(crate::Error::Invalid(
                    "duplicate or unknown application field",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ApplicationOperation {
    FileShareOffered {
        offer: crate::files::ShareOffer,
    },
    FileShareRevoked {
        revoke: crate::files::ShareRevoke,
    },
    MessageSend {
        content: String,
        send_time: i64,
        height: i64,
        version: i64,
        reply_to: Option<i64>,
    },
    MessageEdit {
        content: String,
        send_time: i64,
        version: i64,
    },
    MessageReactionAdd {
        reaction: String,
        send_time: i64,
    },
    MessageReactionRemove {
        reaction: String,
        send_time: i64,
    },
    MessageDelete {
        send_time: i64,
    },
    MessageDeleteLive {
        send_time: i64,
    },
    MessageState {
        message_id: String,
        state: MessageState,
        event_at: i64,
    },
    MessageReceived {
        message_id: String,
        event_at: i64,
    },
    SetChatSecret {
        chat_id: String,
        version: i64,
        wrapping_scheme: String,
        sender: SecretCopy,
        recipient: SecretCopy,
    },
    AddConversation {
        name: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretCopy {
    pub encrypted_secret: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum MessageState {
    Read,
    Received,
    Sent,
    Sending,
}

impl MessageState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Received => "received",
            Self::Sent => "sent",
            Self::Sending => "sending",
        }
    }

    #[expect(
        clippy::should_implement_trait,
        reason = "unknown stored states cannot upgrade delivery"
    )]
    pub fn from_str(value: &str) -> Self {
        match value.to_lowercase().as_str() {
            "read" => Self::Read,
            "received" => Self::Received,
            "sent" => Self::Sent,
            _ => Self::Sending,
        }
    }

    pub fn upgrade(self, other: Self) -> Self {
        if self == Self::Read || other == Self::Read {
            Self::Read
        } else if self == Self::Received || other == Self::Received {
            Self::Received
        } else if self == Self::Sent || other == Self::Sent {
            Self::Sent
        } else {
            Self::Sending
        }
    }
}
