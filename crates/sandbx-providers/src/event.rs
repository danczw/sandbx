/// A provider-agnostic unit of a streamed model turn.
///
/// Fully owned, no lifetimes: this type crosses into sandbx-agent and later
/// sandbx-session, both of which outlive any single HTTP response.
#[derive(Debug, Clone, PartialEq)]
pub enum AgentEvent {
    /// An incremental chunk of assistant-visible text.
    Text { delta: String },
    /// An incremental chunk of the model's extended-thinking text.
    ///
    /// The incremental cryptographic signature Anthropic streams alongside a
    /// thinking block (needed to replay it into a later turn) is accumulated
    /// internally during parsing but has nowhere to go in this shape yet —
    /// nothing threads history back into a request today. Revisit if/when
    /// something does, rather than guessing the field now.
    Thinking { delta: String },
    /// A tool call whose JSON input has fully arrived and parsed.
    ///
    /// Emitted exactly once per call, only after every fragment of its input
    /// has been accumulated and the result parses as JSON.
    ToolCallRequested {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    /// Token accounting for the turn.
    Usage {
        input_tokens: u32,
        output_tokens: u32,
        cache_creation_input_tokens: Option<u32>,
        cache_read_input_tokens: Option<u32>,
    },
    /// The turn ended, and why.
    Stop { reason: StopReason },
}

/// Why a turn ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    EndTurn,
    ToolUse,
    MaxTokens,
    StopSequence,
    /// Forward-compat catch-all: an unrecognized vendor string should not be a
    /// hard parse failure, since new stop reasons ship over time.
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
