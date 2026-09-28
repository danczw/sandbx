use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

/// A request to the Messages API.
///
/// There is no `stream` field: this crate builds no non-streaming path, since
/// the agent loop it feeds always consumes an event stream. The flag is
/// serialized as the constant `true` by the hand-written [`Serialize`] impl
/// below, rather than asked of every caller and every test only to be given
/// the same answer each time.
///
/// `Clone` is part of the contract, not an incidental derive: `stream_chat`
/// takes the request by value, so without it a caller could not retry the same
/// turn after a [`ProviderError::RateLimited`] or [`ProviderError::Transport`]
/// — the retry that those variants exist to invite. The whole tree below
/// derives it for the same reason.
///
/// [`ProviderError::RateLimited`]: crate::ProviderError::RateLimited
/// [`ProviderError::Transport`]: crate::ProviderError::Transport
#[derive(Debug, Clone)]
pub struct MessagesRequest {
    /// A freeform string, not an enum — new model IDs ship regularly, and an
    /// enum would need a code change every release. See the Anthropic API
    /// reference for current model identifiers.
    pub model: String,
    /// This crate has no default opinion on a value; the caller supplies one.
    pub max_tokens: u32,
    /// The system prompt. Omitted from the body entirely when `None`, which is
    /// not the same as sending `null`.
    pub system: Option<String>,
    /// The conversation so far, oldest first.
    pub messages: Vec<RequestMessage>,
    /// Tools the model may call. Omitted from the body entirely when empty.
    pub tools: Vec<ToolDefinition>,
}

impl Serialize for MessagesRequest {
    /// Hand-written rather than derived so `stream` can be a constant in the
    /// wire shape without being a field in the public API. Field order matches
    /// the declaration order above; `system` and `tools` are omitted rather
    /// than sent as `null`/`[]`, which the derive did via
    /// `skip_serializing_if`.
    ///
    /// The destructuring `let` is the point of the first line, not style: a
    /// hand-written impl reading `self.model` and friends silently drops any
    /// field added later, and nothing — not the compiler, not clippy — would
    /// say so. Binding every field by name means a new one fails to compile
    /// here until it is either written to the wire or explicitly ignored, which
    /// is the safety the derive gives for free.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Self {
            model,
            max_tokens,
            system,
            messages,
            tools,
        } = self;

        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("model", model)?;
        map.serialize_entry("max_tokens", max_tokens)?;
        if let Some(system) = system {
            map.serialize_entry("system", system)?;
        }
        map.serialize_entry("messages", messages)?;
        if !tools.is_empty() {
            map.serialize_entry("tools", tools)?;
        }
        map.serialize_entry("stream", &true)?;
        map.end()
    }
}

/// One turn in the conversation.
#[derive(Debug, Clone, Serialize)]
pub struct RequestMessage {
    /// Who produced this turn.
    pub role: Role,
    /// The turn's content blocks, in order.
    pub content: Vec<ContentBlock>,
}

/// Who produced a turn. Serializes lowercase, as the API requires.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// The human (or, for a tool result, the harness acting on their behalf).
    User,
    /// The model.
    Assistant,
}

/// One block of a turn's content, tagged by `type` on the wire.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    /// Plain text.
    Text {
        /// The text itself.
        text: String,
    },
    /// A tool call the model made on a previous turn, replayed back into the
    /// conversation.
    ToolUse {
        /// The vendor's call ID, which the matching [`ToolResult`] must echo.
        ///
        /// [`ToolResult`]: Self::ToolResult
        id: String,
        /// The tool that was called.
        name: String,
        /// The arguments the model produced.
        input: serde_json::Value,
    },
    /// The outcome of running a tool call.
    ToolResult {
        /// The `id` of the [`ToolUse`] block this answers.
        ///
        /// [`ToolUse`]: Self::ToolUse
        tool_use_id: String,
        /// The tool's output, or its error message when `is_error` is set.
        content: String,
        /// `Some(true)` marks the call as failed. Omitted from the body
        /// entirely when `None`, which is not the same as sending `null`.
        #[serde(skip_serializing_if = "Option::is_none")]
        is_error: Option<bool>,
    },
}

/// A tool offered to the model.
#[derive(Debug, Clone, Serialize)]
pub struct ToolDefinition {
    /// The name the model uses to call it.
    pub name: String,
    /// What it does, in prose — this is the model's only guide to when to
    /// reach for it.
    pub description: String,
    /// A plain `serde_json::Value`, not `schemars::Schema` — decouples this
    /// crate from sandbx-tools entirely. Bridging `BuiltinTool::input_schema()`
    /// into this shape is the caller's job.
    pub input_schema: serde_json::Value,
}
