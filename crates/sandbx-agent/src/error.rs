use sandbx_providers::ProviderError;

/// Why a turn did not finish.
///
/// Deliberately not a catch-all for everything that can go wrong inside a turn: a
/// tool that fails is *not* an error here. A refused or malformed tool call is fed
/// back to the model as a `tool_result` marked `is_error`, because the model can
/// act on that and the turn is still healthy. Only a failure that ends the turn
/// reaches this type.
#[derive(Debug)]
pub enum TurnError {
    /// The provider failed, either before the stream opened or partway through it.
    ///
    /// Carried rather than flattened so a caller can reach
    /// [`ProviderError::is_retryable`] and [`ProviderError::retry_after`] without
    /// this crate having to restate that decision.
    Provider(ProviderError),

    /// The stream ended without ever reporting that the turn was over.
    ///
    /// A real provider ends a turn with an `AgentEvent::Stop` or with an `Err`,
    /// never with silence, so this is a wire-format or test-double fault. Reported
    /// rather than treated as a finished turn, which would leave a caller unable
    /// to tell a complete turn from a truncated one.
    StreamEndedWithoutStop,

    /// The model was still asking for tools when the turn ran out of rounds.
    ///
    /// Not a quiet stop: a turn cut off here did not finish, and the partial
    /// transcript is discarded rather than handed back looking complete.
    RoundLimit {
        /// The cap that was reached.
        rounds: usize,
    },

    /// One round outran its streaming bound and the turn was abandoned.
    ///
    /// Distinct from [`Provider`]: the stream was healthy, it simply did not finish
    /// in time, so a retry of the same turn may well succeed.
    ///
    /// [`Provider`]: Self::Provider
    TimedOut {
        /// The bound it exceeded.
        after: std::time::Duration,
    },

    /// A tool's blocking task did not return a result.
    ///
    /// Reachable only if the tool panicked, since the task is awaited to
    /// completion and the runtime outlives it. No built-in does, and
    /// `BuiltinTool` is a closed enum, so no test can inject one that would —
    /// this exists so that a panic surfaces as a typed failure instead of taking
    /// the harness down with it.
    ToolPanicked {
        /// The tool that was running.
        name: String,
    },
}

impl std::fmt::Display for TurnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Provider(error) => write!(f, "provider failed: {error}"),
            Self::StreamEndedWithoutStop => {
                write!(f, "the turn's event stream ended without a stop event")
            }
            Self::RoundLimit { rounds } => {
                write!(f, "still asking for tools after {rounds} rounds")
            }
            Self::TimedOut { after } => {
                write!(f, "a round did not finish streaming within {after:?}")
            }
            Self::ToolPanicked { name } => write!(f, "the {name} tool panicked"),
        }
    }
}

impl std::error::Error for TurnError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Provider(error) => Some(error),
            Self::StreamEndedWithoutStop
            | Self::RoundLimit { .. }
            | Self::TimedOut { .. }
            | Self::ToolPanicked { .. } => None,
        }
    }
}
