/// Handler lifetime for one connection. Authentication and terminal outcome are
/// independent. Applications call `activate` at handler start and `close` after cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    Admitted,
    /// The application accepted responsibility for handling this connection.
    /// This does not imply registry publication, routing availability, handler
    /// readiness, or that the physical transport remains connected.
    Active,
    Closed,
}
