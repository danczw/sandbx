//! The vocabulary a streamed model turn is spoken in: one event per thing that arrived,
//! and the reason the turn ended.
//!
//! A crate rather than a module in the provider crate, because every layer above speaks
//! this vocabulary and only one of them wants a client: the turn loop, the CLI's renderer
//! and `sandbx-tui-transcript`'s fold all name these two types, and the fold names nothing
//! else of a provider's. While they lived beside the clients, the drawing side reached
//! reqwest, rustls and hyper to match on an enum, and carried them on to `sandbx-screen`
//! behind it; both crates now reach neither (#328, #365).
//!
//! A second adapter maps its own frames onto these types rather than extending them, which
//! is the seam `context/decision-provider-seam.md` records. Nothing here derives
//! `Serialize` or `Deserialize`, and nothing here parses: `StopReason::Other` carries a
//! vendor string as opaque data, and the string table that produces one is a private free
//! function in the adapter, so no `StopReason` is built from a wire string outside it
//! (#59).

/// A provider-agnostic unit of a streamed model turn, fully owned so it outlives the
/// HTTP response it came from.
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
    /// An incremental chunk of the model's reasoning text, for a renderer.
    ///
    /// Empty unless the provider crate's `Thinking::Visible` was asked for, and never
    /// the whole block: [`ThinkingBlock`](Self::ThinkingBlock) is what carries one back
    /// into a later request. Not a link, for the same reason as on
    /// [`Stop`](Self::Stop): the edge back to that crate would be a cycle.
    Thinking {
        /// The new thinking text to append; not the accumulated text so far.
        delta: String,
    },
    /// A reasoning block whose text and signature have both fully arrived.
    ///
    /// Only ever emitted for a block that carries a signature: one without is
    /// unreplayable, and passing it on would put a rejected request in a caller's
    /// history rather than lose one block.
    ThinkingBlock {
        /// The accumulated reasoning text, empty when the summary was not asked for.
        text: String,
        /// Opaque. Never log, render or store it; see
        /// `context/decision-thinking-replay.md`.
        signature: String,
    },
    /// Reasoning the provider withheld, carrying an opaque blob in place of text.
    ///
    /// Replayed on the same terms as [`ThinkingBlock`](Self::ThinkingBlock): a
    /// consumer that handles one and drops the other leaves the gap the provider
    /// checks for.
    RedactedThinking {
        /// Opaque. Never log, render or store it.
        data: String,
    },
    /// A tool call whose JSON input has fully arrived and parsed, once per call.
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
    /// At most once, carrying the last figures reported: Anthropic restates the counts
    /// cumulatively on every `message_delta`, so summing them double-counts. `None` is
    /// "not reported", not a reported zero.
    Usage {
        /// Tokens in the request, excluding anything served from cache.
        input_tokens: Option<u32>,
        /// Tokens generated, extended thinking included, so it can exceed the reply.
        output_tokens: Option<u32>,
        /// Tokens written to the prompt cache.
        cache_write_tokens: Option<u32>,
        /// Tokens read from the prompt cache.
        cache_read_tokens: Option<u32>,
    },
    /// The turn ended, and why.
    ///
    /// At `message_stop`, not when a stop reason is first seen; a turn that never
    /// reaches it yields the provider crate's `ProviderError::StreamEndedUnexpectedly`
    /// instead. Not a link: the edge back to that crate would be a cycle.
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
    /// `message_delta.stop_reason` is nullable, so a stream can reach `message_stop`
    /// with nothing having said why.
    Unspecified,
    /// A reason this enum does not model, verbatim: new ones ship over time, and
    /// which strings map here is an adapter's business.
    Other(String),
}
