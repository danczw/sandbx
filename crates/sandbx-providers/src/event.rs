/// A provider-agnostic unit of a streamed model turn.
///
/// Fully owned, no lifetimes: this type crosses into sandbx-agent and later
/// sandbx-session, both of which outlive any single HTTP response.
#[derive(Debug, Clone, PartialEq)]
pub enum AgentEvent {
    /// An incremental chunk of assistant-visible text.
    ///
    /// Where one text block ends and the next begins is deliberately not recoverable:
    /// a `content_block_stop` is only reported for a `tool_use` block, so a consumer
    /// rebuilding content coalesces consecutive text blocks into one. That is lossless
    /// for replay — the concatenation is identical and the API accepts a single text
    /// block — but it is a contract, not an accident, and `run_turn` relies on it.
    Text {
        /// The new text to append; not the accumulated text so far.
        delta: String,
    },
    /// An incremental chunk of the model's extended-thinking text.
    ///
    /// The incremental cryptographic signature Anthropic streams alongside a
    /// thinking block (needed to replay it into a later turn) is *discarded*, and
    /// [`ContentBlock`] has no thinking variant to put one in, so a thinking block
    /// cannot be replayed at all. `sandbx-agent`'s `run_turn` does thread history back
    /// into a request, and drops thinking on the way. Harmless while
    /// [`MessagesRequest`] cannot enable extended thinking in the first place;
    /// accumulate the signature in `wire/accumulate.rs` and add a field here when it
    /// can. Tracked as #85.
    ///
    /// [`ContentBlock`]: crate::ContentBlock
    /// [`MessagesRequest`]: crate::MessagesRequest
    Thinking {
        /// The new thinking text to append; not the accumulated text so far.
        delta: String,
    },
    /// A tool call whose JSON input has fully arrived and parsed.
    ///
    /// Emitted exactly once per call, only after every fragment of its input
    /// has been accumulated and the result parses as JSON.
    ToolCallRequested {
        /// The vendor's call ID, to echo in the `tool_result` block that
        /// answers this call.
        id: String,
        /// The tool's name as the model asked for it, for the caller to match
        /// against its own registry.
        name: String,
        /// The fully accumulated, parsed arguments.
        input: serde_json::Value,
    },
    /// Token accounting for the turn.
    ///
    /// Emitted at most once per turn, carrying the last figures the API
    /// reported — Anthropic restates the counts cumulatively on every
    /// `message_delta`, so summing several of these would double-count. A turn
    /// that reported no counts at all emits no `Usage` event.
    ///
    /// Every field is optional because the API may omit any of them: `None`
    /// means "not reported", which is deliberately distinguishable from a
    /// reported zero.
    Usage {
        /// Tokens in the request, excluding anything served from cache.
        input_tokens: Option<u32>,
        /// Tokens the model generated, extended thinking included — so this can
        /// exceed the visible reply.
        output_tokens: Option<u32>,
        /// Tokens written to the prompt cache.
        cache_creation_input_tokens: Option<u32>,
        /// Tokens read from the prompt cache.
        cache_read_input_tokens: Option<u32>,
    },
    /// The turn ended, and why.
    ///
    /// Emitted when the stream's `message_stop` arrives, not when a stop reason
    /// is first seen, so "the turn ended" has a single source of truth. A turn
    /// that never reaches `message_stop` produces an `Err` instead — see
    /// [`ProviderError::StreamEndedUnexpectedly`] — never silence.
    ///
    /// [`ProviderError::StreamEndedUnexpectedly`]: crate::ProviderError::StreamEndedUnexpectedly
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
    /// The model wants a tool run before continuing (`tool_use`); the caller
    /// is expected to answer with `tool_result` blocks.
    ToolUse,
    /// The reply was cut off at `max_tokens`, mid-thought.
    MaxTokens,
    /// A caller-supplied stop sequence was produced (`stop_sequence`).
    StopSequence,
    /// The turn ended without the API ever reporting a reason.
    ///
    /// `message_delta.stop_reason` is nullable, so a stream can reach
    /// `message_stop` with nothing having said why. Reported explicitly rather
    /// than by omitting the [`AgentEvent::Stop`] event, which would leave a
    /// caller unable to distinguish a finished turn from a truncated one.
    Unspecified,
    /// Forward-compat catch-all: an unrecognized vendor string should not be a
    /// hard parse failure, since new stop reasons ship over time. Carries the
    /// vendor's string verbatim.
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
