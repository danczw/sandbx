//! What to ask a model for, in this crate's own vocabulary.
//!
//! Plain data: no `Serialize` anywhere below, because the body shape, its field
//! names and its required-together rules belong to one API. An adapter owns those;
//! see `context/decision-provider-seam.md`.

/// One request for one model turn.
///
/// `Clone` is part of the contract, here and down the whole tree, because
/// `stream_chat` takes the prompt by value and a retry needs a second copy.
#[derive(Debug, Clone, PartialEq)]
pub struct Prompt {
    /// A freeform string, not an enum: new model IDs ship regularly.
    pub model: String,
    /// A ceiling on the turn's output. No default opinion on a value.
    pub max_output_tokens: u32,
    /// Standing instructions, outside the conversation.
    pub system: Option<String>,
    /// The conversation so far, oldest first.
    pub messages: Vec<RequestMessage>,
    /// Tools the model may call.
    pub tools: Vec<ToolDefinition>,
    /// Whether the model may call one. `None` leaves the choice to the model.
    pub tool_choice: Option<ToolChoice>,
    /// Whether to ask for the model's reasoning. `None` takes the provider's default,
    /// which on current Anthropic models is reasoning that happens but is not shown.
    pub thinking: Option<Thinking>,
}

/// What the model may do with the tools a prompt defines.
///
/// One variant, an absent field already meaning the provider's default: an `Auto`
/// would describe a request indistinguishable from omitting this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolChoice {
    /// Call none of them, so the reply is prose.
    ///
    /// Not the same as offering no `tools`: a conversation replaying `tool_use` or
    /// `tool_result` still needs the definitions those blocks name.
    None,
}

/// What to ask for of the model's reasoning.
///
/// One variant, for [`ToolChoice`]'s reason: on current Anthropic models reasoning
/// is on whether or not this is set, and all that setting it changes is whether the
/// text comes back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Thinking {
    /// Stream the reasoning text, so a caller can show it.
    Visible,
}

/// One turn in the conversation.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestMessage {
    /// Who produced it. A conversation whose first turn is not [`Role::User`] is
    /// one no provider accepts.
    pub role: Role,
    /// Content blocks, in order.
    pub content: Vec<ContentBlock>,
}

/// Who produced a turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The human (or, for a tool result, the harness acting on their behalf).
    User,
    /// The model, on a turn being replayed back out of history.
    Assistant,
}

/// One block of a turn's content.
#[derive(Debug, Clone, PartialEq)]
pub enum ContentBlock {
    /// Prose, the only block kind a first user turn needs.
    Text {
        /// Sent as given.
        text: String,
    },
    /// The model's reasoning on a turn being replayed back.
    ///
    /// Both fields go back exactly as they arrived, the signature being checked
    /// against every message ahead of the block; see
    /// `context/decision-thinking-replay.md`.
    Thinking {
        /// The reasoning text, which is empty unless [`Thinking::Visible`] was set.
        text: String,
        /// Opaque, and never logged, rendered or stored.
        signature: String,
    },
    /// Reasoning the provider withheld, carrying an opaque blob in place of text.
    ///
    /// Replayed on the same terms as [`Thinking`](Self::Thinking).
    RedactedThinking {
        /// Opaque, and never logged, rendered or stored.
        data: String,
    },
    /// A tool call from a previous turn, replayed back into the conversation.
    ToolUse {
        /// The provider's call ID, which the answering
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
        /// `Some(true)` marks the call as failed.
        is_error: Option<bool>,
    },
}

impl ContentBlock {
    /// Whether this is reasoning, either kind.
    ///
    /// The two travel together: a filter that keeps one and drops the other leaves a
    /// gap in the reasoning the provider checks for.
    pub fn is_thinking(&self) -> bool {
        matches!(self, Self::Thinking { .. } | Self::RedactedThinking { .. })
    }
}

/// A tool offered to the model.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolDefinition {
    /// The name the model uses to call it.
    pub name: String,
    /// What it does, in prose — the model's only guide to when to reach for it.
    pub description: String,
    /// A plain `Value`, not `schemars::Schema`, so this crate need not depend on
    /// sandbx-tools.
    pub schema: serde_json::Value,
}
