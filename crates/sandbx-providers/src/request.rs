use serde::Serialize;

/// A request to the Messages API.
#[derive(Debug, Serialize)]
pub struct MessagesRequest {
    /// A freeform string, not an enum — new model IDs ship regularly, and an
    /// enum would need a code change every release. See the Anthropic API
    /// reference for current model identifiers.
    pub model: String,
    /// This crate has no default opinion on a value; the caller supplies one.
    pub max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    pub messages: Vec<RequestMessage>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolDefinition>,
    /// Always `true` in this crate: no non-streaming path is built, since the
    /// agent loop this feeds always consumes an event stream.
    pub stream: bool,
}

#[derive(Debug, Serialize)]
pub struct RequestMessage {
    pub role: Role,
    pub content: Vec<ContentBlock>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Assistant,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    Text {
        text: String,
    },
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    ToolResult {
        tool_use_id: String,
        content: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        is_error: Option<bool>,
    },
}

#[derive(Debug, Serialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    /// A plain `serde_json::Value`, not `schemars::Schema` — decouples this
    /// crate from sandbx-tools entirely. Bridging `BuiltinTool::input_schema()`
    /// into this shape is the caller's job.
    pub input_schema: serde_json::Value,
}
