use sandbx_providers::ProviderError;

/// Why a turn did not finish.
///
/// A tool that fails is not an error here: a refused or malformed call goes back to the
/// model as a `tool_result` marked `is_error` and the turn is still healthy. Only a
/// failure that ends the turn reaches this type.
#[derive(Debug)]
pub enum TurnError {
    /// The provider failed, either before the stream opened or partway through it.
    ///
    /// Carried rather than flattened so a caller can reach
    /// [`ProviderError::is_retryable`] and [`ProviderError::retry_after`].
    Provider(ProviderError),

    /// The stream ended without ever reporting that the turn was over.
    ///
    /// A wire-format or test-double fault: a real provider ends a turn with
    /// `AgentEvent::Stop` or an `Err`, never silence, which a caller could not tell from
    /// a truncated turn.
    StreamEndedWithoutStop,

    /// The model was still asking for tools when the turn ran out of rounds.
    ///
    /// The partial transcript is discarded rather than handed back looking complete.
    RoundLimit {
        /// The cap that was reached.
        rounds: usize,
    },

    /// The model stopped producing content while a tool call was still unanswered.
    ///
    /// The transcript ends in a `tool_result` the model never answered, so returning `Ok`
    /// would break the request *after* the one that went wrong. Discarded.
    ///
    /// An empty *first* round is not this: nothing is unanswered behind it, so it comes
    /// back as an empty turn.
    EndedMidToolUse,

    /// One round outran its streaming bound and the turn was abandoned.
    ///
    /// Distinct from [`Provider`]: the stream was healthy, so a retry may well succeed.
    ///
    /// [`Provider`]: Self::Provider
    TimedOut {
        /// The bound it exceeded.
        after: std::time::Duration,
    },

    /// A tool's blocking task did not return a result.
    ///
    /// Almost always a panic in the tool; a runtime shut down mid-flight produces the
    /// same thing. Typed rather than resumed, so a panic names the tool instead of taking
    /// down whichever task owns the turn.
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
