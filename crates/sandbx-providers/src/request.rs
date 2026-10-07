use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

/// A request to the Messages API.
///
/// No `stream` field: the [`Serialize`] impl below writes it as the constant `true`.
/// `Clone` is part of the contract, here and down the whole tree, because
/// `stream_chat` takes the request by value and a retry needs a second copy.
#[derive(Debug, Clone)]
pub struct MessagesRequest {
    /// A freeform string, not an enum: new model IDs ship regularly.
    pub model: String,
    /// Required by the API; this crate has no default opinion on a value.
    pub max_tokens: u32,
    /// The system prompt, omitted from the body when `None`, not sent as `null`.
    pub system: Option<String>,
    /// The conversation so far, oldest first.
    pub messages: Vec<RequestMessage>,
    /// Tools the model may call. Omitted from the body entirely when empty.
    pub tools: Vec<ToolDefinition>,
    /// Whether the model may call one. Omitted when `None`, which the API reads as its
    /// own default of leaving the choice to the model.
    pub tool_choice: Option<ToolChoice>,
}

/// What the model may do with the tools a request defines.
///
/// One variant, an absent field already meaning the API's default: an `Auto` would
/// serialize to a request indistinguishable from omitting this one.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ToolChoice {
    /// Call none of them, so the reply is prose.
    ///
    /// Not the same as sending no `tools`: the API refuses a conversation replaying
    /// `tool_use` or `tool_result` without the definitions those blocks name.
    None,
}

impl Serialize for MessagesRequest {
    /// Hand-written so `stream` is a wire constant without being a public field, and
    /// `system`/`tools`/`tool_choice` are omitted rather than sent as `null`/`[]`. The
    /// destructuring `let` makes a field added later fail to compile until it is written
    /// out.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Self {
            model,
            max_tokens,
            system,
            messages,
            tools,
            tool_choice,
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
        // Only alongside `tools`: the API rejects a choice over tools that were not
        // defined, so an empty list with a choice set is a request it refuses.
        if let Some(tool_choice) = tool_choice.filter(|_| !tools.is_empty()) {
            map.serialize_entry("tool_choice", &tool_choice)?;
        }
        map.serialize_entry("stream", &true)?;
        map.end()
    }
}

/// One turn in the conversation.
#[derive(Debug, Clone, Serialize)]
pub struct RequestMessage {
    /// Who produced it. The API rejects a conversation whose first turn is not
    /// [`Role::User`].
    pub role: Role,
    /// Content blocks, in order.
    pub content: Vec<ContentBlock>,
}

/// Who produced a turn. Serializes lowercase, as the API requires.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// The human (or, for a tool result, the harness acting on their behalf).
    User,
    /// The model, on a turn being replayed back out of history.
    Assistant,
}

/// One block of a turn's content, tagged by `type` on the wire.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    /// Prose, the only block kind a first user turn needs.
    Text {
        /// Sent as given.
        text: String,
    },
    /// A tool call from a previous turn, replayed back into the conversation.
    ToolUse {
        /// The vendor's call ID, which the answering
        /// [`ToolResult`](Self::ToolResult) must echo.
        id: String,
        /// The tool's name, as it stood in the model's original call.
        name: String,
        /// Replayed verbatim rather than re-serialized from a parsed form.
        input: serde_json::Value,
    },
    /// The outcome of running a tool call.
    ToolResult {
        /// The `id` of the [`ToolUse`](Self::ToolUse) block this answers.
        tool_use_id: String,
        /// The tool's output, or its error message when `is_error` is set.
        content: String,
        /// `Some(true)` marks the call as failed; omitted from the body when `None`.
        #[serde(skip_serializing_if = "Option::is_none")]
        is_error: Option<bool>,
    },
}

/// A tool offered to the model.
#[derive(Debug, Clone, Serialize)]
pub struct ToolDefinition {
    /// The name the model uses to call it.
    pub name: String,
    /// What it does, in prose — the model's only guide to when to reach for it.
    pub description: String,
    /// A plain `Value`, not `schemars::Schema`, so this crate need not depend on
    /// sandbx-tools.
    pub input_schema: serde_json::Value,
}
