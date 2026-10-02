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

    /// The model stopped producing content while a tool call was still unanswered.
    ///
    /// The round arrived with no content blocks at all, and the transcript so far
    /// ends in the `tool_result` the model asked for. Not handed back as a finished
    /// turn: a caller appends its own user message after what it is given, and the
    /// API rejects two consecutive user turns — so returning this as `Ok` would
    /// break the request *after* the one that went wrong. Same treatment, and the
    /// same reason, as [`RoundLimit`].
    ///
    /// An empty *first* round is not this: there is nothing unanswered behind it, so
    /// it comes back as an empty turn.
    ///
    /// [`RoundLimit`]: Self::RoundLimit
    EndedMidToolUse,

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
    /// Almost always means the tool panicked; a runtime shut down while the task was
    /// in flight produces the same thing, which a UI exit path can reach. No built-in
    /// panics, and `BuiltinTool` is a closed enum, so no test can inject one that
    /// would — this exists so a panic surfaces as a typed failure naming the tool,
    /// rather than taking the harness down or being resumed into whichever task owns
    /// the turn.
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
            Self::EndedMidToolUse => {
                write!(
                    f,
                    "the turn ended with a tool result the model never answered"
                )
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
            | Self::EndedMidToolUse
            | Self::TimedOut { .. }
            | Self::ToolPanicked { .. } => None,
        }
    }
}
