/// Why a tool call did not produce a result.
///
/// The variants are distinguished because the agent reacts to them differently:
/// a refusal means "ask for something else", bad input means "call it correctly",
/// and a failure means "the operation itself went wrong". Collapsing them would
/// leave the model guessing.
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
    /// Separate from [`Failed`] because the agent should react differently: a
    /// command that failed will fail again, while one that ran out of time might
    /// succeed if narrowed or given longer.
    ///
    /// [`Failed`]: Self::Failed
    TimedOut {
        /// What was attempted.
        subject: String,
        /// The limit it exceeded.
        after: std::time::Duration,
    },
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied { subject, reason } => {
                write!(f, "refused by the sandbox policy: {subject} ({reason})")
            }
            Self::BadInput { detail } => write!(f, "invalid tool arguments: {detail}"),
            Self::Failed { subject, detail } => write!(f, "{subject} failed: {detail}"),
            Self::TimedOut { subject, after } => {
                write!(f, "{subject} timed out after {after:?} and was killed")
            }
        }
    }
}

impl std::error::Error for ToolError {}
