use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// A flag one side raises to stop a command another side is waiting on.
///
/// Every clone is the same flag: the caller keeps one and hands another to
/// [`SandboxedCommand::cancel_on`](crate::SandboxedCommand::cancel_on). Raised once and for
/// good, so a token is minted per unit of work to stop, never reused.
///
/// A polled flag and not a channel: a run already wakes every few milliseconds to ask the
/// child whether it has exited, and a second thing to block on would need a second thing
/// to wake it.
#[derive(Debug, Clone, Default)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    /// A token nobody has raised.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ask whoever holds a clone to stop. Idempotent.
    pub fn raise(&self) {
        // `Relaxed`: the flag publishes nothing else, so there is no other write for a
        // reader to be ordered against.
        self.0.store(true, Ordering::Relaxed);
    }

    /// Whether any clone has been raised.
    pub fn is_raised(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
#[path = "cancel_tests.rs"]
mod tests;
