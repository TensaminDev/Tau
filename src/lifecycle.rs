/// Handler lifetime for one connection. Authentication and terminal outcome are
/// independent. Applications call `activate` at handler start and `close` after cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    Admitted,
    Active,
    Closed,
}
