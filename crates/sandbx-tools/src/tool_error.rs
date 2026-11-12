use std::fmt;
use std::time::Duration;

/// Why a tool call did not produce a result.
///
/// Split by the agent's next move: a refusal means "ask for something else", bad
/// input "call it correctly", a failure "the operation went wrong".
///
/// A `reason` or `detail` reaches the model inside a `tool_result`, which a
/// prompt-injected model relays, so neither may name a grant the caller does not already
/// hold: the refusal for a path outside every root stays indistinguishable from any other.
#[derive(Debug)]
pub enum ToolError {
    /// The sandbox policy refused the operation.
    Denied {
        /// What was attempted.
        subject: String,
        /// Why it was refused, for the model to act on.
        reason: String,
    },

    /// The arguments did not match the tool's schema.
    BadInput {
        /// What was wrong with them.
        detail: String,
    },

    /// The operation was permitted but did not succeed.
    Failed {
        /// What was attempted.
        subject: String,
        /// The underlying failure.
        detail: String,
    },

    /// The operation ran past its time limit and was killed.
    ///
    /// Separate from [`Failed`](Self::Failed): a command that failed will fail
    /// again, one that ran out of time might succeed if narrowed or given longer.
    TimedOut {
        /// What was attempted.
        subject: String,
        /// The limit it exceeded.
        after: Duration,
    },

    /// The operation was killed because the caller stopped waiting for it.
    ///
    /// Separate from [`TimedOut`](Self::TimedOut): no limit was hit, so there is nothing to
    /// narrow or lengthen, and the operation may have changed state before it died.
    Cancelled {
        /// What was attempted.
        subject: String,
    },
}

impl fmt::Display for ToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied { subject, reason } => {
                write!(f, "refused by the sandbox policy: {subject} ({reason})")
            }
            Self::BadInput { detail } => write!(f, "invalid tool arguments: {detail}"),
            Self::Failed { subject, detail } => write!(f, "{subject} failed: {detail}"),
            Self::TimedOut { subject, after } => {
                write!(f, "{subject} timed out after {after:?} and was killed")
            }
            Self::Cancelled { subject } => {
                write!(f, "{subject} was cancelled and killed before it finished")
            }
        }
    }
}

impl std::error::Error for ToolError {}
