/// Namespace tag carried in the wire identity of a relay next hop. A user ID
/// and an Iota ID with the same numeric value must not select the same route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteTarget {
    User(u64),
    Iota(u64),
}

const TARGET_KIND_MASK: u64 = 0xC000_0000_0000_0000;
const TARGET_ID_MASK: u64 = (1_u64 << 48) - 1;
const USER_TARGET_KIND: u64 = 0x4000_0000_0000_0000;
const IOTA_TARGET_KIND: u64 = 0x8000_0000_0000_0000;

impl RouteTarget {
    pub fn wire_id(self) -> Option<u64> {
        let (kind, id) = match self {
            Self::User(id) => (USER_TARGET_KIND, id),
            Self::Iota(id) => (IOTA_TARGET_KIND, id),
        };
        (id > 0 && id <= TARGET_ID_MASK).then_some(kind | id)
    }

    pub fn from_wire_id(value: u64) -> Option<Self> {
        let id = value & TARGET_ID_MASK;
        if id == 0 || value & !(TARGET_KIND_MASK | TARGET_ID_MASK) != 0 {
            return None;
        }

        match value & TARGET_KIND_MASK {
            USER_TARGET_KIND => Some(Self::User(id)),
            IOTA_TARGET_KIND => Some(Self::Iota(id)),
            _ => None,
        }
    }

    pub const fn id(self) -> u64 {
        match self {
            Self::User(id) | Self::Iota(id) => id,
        }
    }
}

impl std::fmt::Display for RouteTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User(id) => write!(formatter, "User({id})"),
            Self::Iota(id) => write!(formatter, "Iota({id})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RouteTarget;

    fn wire(target: RouteTarget) -> u64 {
        let Some(value) = target.wire_id() else {
            panic!("valid route target was rejected");
        };
        value
    }

    #[test]
    fn route_target_round_trips_both_namespaces() {
        assert_eq!(
            RouteTarget::from_wire_id(wire(RouteTarget::User(7))),
            Some(RouteTarget::User(7))
        );
        assert_eq!(
            RouteTarget::from_wire_id(wire(RouteTarget::Iota(7))),
            Some(RouteTarget::Iota(7))
        );
    }

    #[test]
    fn raw_id_is_not_a_valid_typed_route() {
        assert_ne!(RouteTarget::from_wire_id(42), Some(RouteTarget::Iota(42)));
        assert_eq!(RouteTarget::from_wire_id(42), None);
    }

    #[test]
    fn zero_and_oversized_ids_are_rejected() {
        assert_eq!(RouteTarget::User(0).wire_id(), None);
        assert_eq!(RouteTarget::from_wire_id((1 << 48) | 1), None);
    }

    #[test]
    fn namespaces_do_not_collide() {
        assert_ne!(wire(RouteTarget::User(7)), wire(RouteTarget::Iota(7)));
    }
}
