use mtp::codec::{CommunicationType, CommunicationValue};

/// Message frames that must only travel inside a sealed relay envelope.
pub const RELAY_ONLY_TYPES: &[CommunicationType] = &[
    CommunicationType::MessageSend,
    CommunicationType::MessageLive,
    CommunicationType::MessageState,
    CommunicationType::MessageEdit,
    CommunicationType::MessageEditLive,
    CommunicationType::MessageReactionAdd,
    CommunicationType::MessageReactionRemove,
    CommunicationType::MessageReactionLive,
    CommunicationType::MessageDelete,
    CommunicationType::MessageDeleteLive,
    CommunicationType::MessageOtherIota,
    CommunicationType::SetChatSecret,
    CommunicationType::FileShareOffered,
    CommunicationType::FileShareRevoked,
    CommunicationType::SendChat,
    CommunicationType::SettingsSave,
    CommunicationType::GlobalSettingsSave,
    CommunicationType::AddConversation,
    CommunicationType::AddCommunity,
    CommunicationType::RemoveCommunity,
];

/// These frames are never client operations, even when a caller includes them
/// in a local request allowlist. Transport authentication remains mandatory.
pub const CHAT_SECRET_PEER_CONTROL_TYPES: &[CommunicationType] = &[
    CommunicationType::ChatSecretRecoveryRequest,
    CommunicationType::ChatSecretRecoveryResponse,
    CommunicationType::ChatSecretRecoveryUnavailable,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageSecurityClass {
    RelayOnly,
    AuthenticatedPeerControl,
    AuthenticatedLocalRequest,
    Unsupported,
}

/// Classify a frame. The relay-only list is shared; the peer-control list is
/// application policy, because an Omikron and a hosted Iota accept different
/// peer-facing operations. Local operations also require an explicit allowlist.
/// Consumers must reject Unsupported. Classification does not authenticate the
/// sender or authorize the operation.
pub fn message_security_class_with(
    frame: &CommunicationValue,
    peer_control_types: &[CommunicationType],
    local_request_types: &[CommunicationType],
) -> MessageSecurityClass {
    let Some(kind) = frame
        .type_map()
        .and_then(|map| map.comm_enum_id(frame.get_type().0))
    else {
        return MessageSecurityClass::Unsupported;
    };
    if RELAY_ONLY_TYPES.contains(&kind) {
        MessageSecurityClass::RelayOnly
    } else if peer_control_types.contains(&kind) {
        MessageSecurityClass::AuthenticatedPeerControl
    } else if CHAT_SECRET_PEER_CONTROL_TYPES.contains(&kind) {
        MessageSecurityClass::Unsupported
    } else if local_request_types.contains(&kind) {
        MessageSecurityClass::AuthenticatedLocalRequest
    } else {
        MessageSecurityClass::Unsupported
    }
}

#[cfg(test)]
mod tests {
    use super::{MessageSecurityClass, message_security_class_with};
    use mtp::codec::{CommunicationType, CommunicationValue};

    #[test]
    fn relay_only_types_are_classified_before_policy() {
        let frame = CommunicationValue::new(CommunicationType::MessageSend);
        assert_eq!(
            message_security_class_with(&frame, &[], &[CommunicationType::MessageSend]),
            MessageSecurityClass::RelayOnly
        );
    }

    #[test]
    fn peer_control_list_is_application_policy() {
        let frame = CommunicationValue::new(CommunicationType::MessagesGet);
        assert_eq!(
            message_security_class_with(&frame, &[CommunicationType::MessagesGet], &[]),
            MessageSecurityClass::AuthenticatedPeerControl
        );
        assert_eq!(
            message_security_class_with(&frame, &[], &[CommunicationType::MessagesGet]),
            MessageSecurityClass::AuthenticatedLocalRequest
        );
        assert_eq!(
            message_security_class_with(&frame, &[], &[]),
            MessageSecurityClass::Unsupported
        );
    }

    #[test]
    fn unknown_wire_types_are_unsupported() {
        let map = mtp::type_map::TypeMap::latest();
        let frame = CommunicationValue::new_with_type_map(CommunicationType::Ping, &map);
        let mut bytes = frame.to_bytes().unwrap();
        bytes[4..6].copy_from_slice(&u16::MAX.to_be_bytes());
        let unknown = CommunicationValue::from_bytes_with(&bytes, &map).unwrap();
        assert_eq!(
            message_security_class_with(
                &unknown,
                &[CommunicationType::Ping],
                &[CommunicationType::Ping]
            ),
            MessageSecurityClass::Unsupported
        );
    }

    #[test]
    fn recovery_control_cannot_be_misclassified_as_a_local_client_request() {
        for kind in super::CHAT_SECRET_PEER_CONTROL_TYPES {
            let frame = CommunicationValue::new(*kind);
            assert_eq!(
                message_security_class_with(&frame, &[], &[*kind]),
                MessageSecurityClass::Unsupported
            );
            assert_eq!(
                message_security_class_with(&frame, &[*kind], &[]),
                MessageSecurityClass::AuthenticatedPeerControl
            );
        }
    }
}
