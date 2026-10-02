/// A provider-agnostic unit of a streamed model turn.
///
/// Fully owned, no lifetimes: this type outlives the HTTP response it came from.
#[derive(Debug, Clone, PartialEq)]
pub enum AgentEvent {
    /// An incremental chunk of assistant-visible text.
    ///
    /// Block boundaries are not recoverable: `content_block_stop` is surfaced only
    /// for a `tool_use` block, so a consumer rebuilding content coalesces
    /// consecutive text blocks into one.
    Text {
        /// The new text to append; not the accumulated text so far.
        delta: String,
    },
    /// An incremental chunk of the model's extended-thinking text.
    ///
    /// The signature needed to replay a thinking block into a later turn is
    /// discarded, and [`ContentBlock`](crate::ContentBlock) has no variant to hold
    /// one; see #85.
    Thinking {
        /// The new thinking text to append; not the accumulated text so far.
        delta: String,
    },
    /// A tool call whose JSON input has fully arrived and parsed, emitted once per
    /// call after every fragment of that input is accumulated.
    ToolCallRequested {
        /// The vendor's call ID, to echo in the answering `tool_result` block.
        id: String,
        /// The tool's name as the model asked for it.
        name: String,
        /// The fully accumulated, parsed arguments.
        input: serde_json::Value,
    },
    /// Token accounting for the turn.
    ///
    /// Emitted at most once, carrying the last figures reported: Anthropic restates
    /// the counts cumulatively on every `message_delta`, so summing several would
    /// double-count. Every field is `Option` because the API may omit any of them —
    /// `None` is "not reported", not a reported zero.
    Usage {
        /// Tokens in the request, excluding anything served from cache.
        input_tokens: Option<u32>,
        /// Tokens generated, extended thinking included, so this can exceed the reply.
        output_tokens: Option<u32>,
        /// Tokens written to the prompt cache.
        cache_creation_input_tokens: Option<u32>,
        /// Tokens read from the prompt cache.
        cache_read_input_tokens: Option<u32>,
    },
    /// The turn ended, and why.
    ///
    /// Emitted at `message_stop`, not when a stop reason is first seen; a turn that
    /// never reaches it yields
    /// [`StreamEndedUnexpectedly`](crate::ProviderError::StreamEndedUnexpectedly).
    Stop {
        /// Why it ended, or [`StopReason::Unspecified`] when the API never said.
        reason: StopReason,
    },
}

/// Why a turn ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// The model finished its reply of its own accord (`end_turn`).
    EndTurn,
    /// The model wants a tool run (`tool_use`); answer with `tool_result` blocks.
    ToolUse,
    /// The reply was cut off at `max_tokens`, mid-thought.
    MaxTokens,
    /// A caller-supplied stop sequence was produced (`stop_sequence`).
    StopSequence,
    /// The turn ended without the API ever reporting a reason:
    /// `message_delta.stop_reason` is nullable, so a stream can reach
    /// `message_stop` with nothing having said why.
    Unspecified,
    /// An unrecognized vendor string, verbatim: new stop reasons ship over time.
    Other(String),
}

impl StopReason {
    pub(crate) fn from_wire(value: &str) -> Self {
        match value {
            "end_turn" => Self::EndTurn,
            "tool_use" => Self::ToolUse,
            "max_tokens" => Self::MaxTokens,
            "stop_sequence" => Self::StopSequence,
            other => Self::Other(other.to_string()),
        }
    }
}
