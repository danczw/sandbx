//! What a transcript line holds: one turn of the conversation, and what the request for it
//! cost.
//!
//! Mirrors `sandbx_prompt`'s `RequestMessage`, `Role` and `ContentBlock`, `sandbx_compact`'s
//! `PromptUsage`, and, with one stop more, `sandbx_turn`'s `TurnStop`, declared here rather than
//! imported because a transcript is a file format, and one that moved whenever a request type
//! moved would not be.
//! `sandbx-session-bridge` translates, and fails to compile on a new block kind; `sandbx-cli`
//! translates the stop, the bridge having no `sandbx-turn` edge to name it by.
//! `sandbx-session-store`'s `record` has the line format these sit in.

use serde::{Deserialize, Serialize};

/// One turn in a stored conversation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    /// Who produced this turn.
    pub role: Role,
    /// Content blocks, in order.
    pub content: Vec<Content>,
}

/// Who produced a turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// The human, or the harness answering a tool call on their behalf.
    User,
    /// The model.
    Assistant,
}

/// One block of a turn's content, tagged by `type` on the wire.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Content {
    /// Prose.
    Text {
        /// Stored as given.
        text: String,
    },
    /// A tool call the model made.
    ToolUse {
        /// The vendor's call id, echoed by the answering [`ToolResult`](Self::ToolResult).
        id: String,
        /// The tool's name, as the model called it.
        name: String,
        /// Stored verbatim rather than re-serialized from a parsed form.
        input: serde_json::Value,
    },
    /// The outcome of running a tool call.
    ToolResult {
        /// The `id` of the [`ToolUse`](Self::ToolUse) block this answers.
        tool_use_id: String,
        /// The tool's output, or its error message when `is_error` is set.
        content: String,
        /// `Some(true)` marks the call as failed; absent from the line when `None`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        is_error: Option<bool>,
    },
}

/// What the provider counted the prompt at, as of the last turn that reported one.
///
/// Stored because it is recoverable only when the turn reports it, and a resume without
/// it cannot tell whether the history already fills the context window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    /// Tokens in the request, excluding anything served from cache.
    pub input_tokens: Option<u32>,
    /// Tokens read from the prompt cache.
    pub cache_read_input_tokens: Option<u32>,
    /// Tokens written to the prompt cache.
    pub cache_creation_input_tokens: Option<u32>,
}

/// How a stored turn came to an end, which its messages cannot always show: a turn out of
/// rounds and one the gate aborted both end on tool calls the model never answered.
///
/// No payload, unlike `sandbx_turn`'s: resume says which stop it was, never the cap. Two
/// stops more, too. `sandbx-cli`'s wrap-up merge takes the tool-less round's `Answered` over the
/// cap, which would store a capped turn as a whole one; [`Summarised`](Self::Summarised) keeps it.
/// And `sandbx_turn`'s `Interrupted` is split by who stopped it, a hangup being a turn nobody
/// watched (#271).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnStop {
    /// The model stopped asking for tools.
    Answered,
    /// The turn ran out of rounds.
    RoundLimit,
    /// The turn ran out of rounds, and a tool-less round answered it.
    Summarised,
    /// The gate ended the turn, having lost whatever it decides with.
    GateAborted,
    /// The operator stopped the turn, and the round it was in is not stored.
    Interrupted,
    /// The terminal went away, which stopped the turn as [`Interrupted`](Self::Interrupted)
    /// does.
    HungUp,
}

/// One turn's worth of everything a transcript records; they travel together because
/// threading them apart leaves accounting that describes a different conversation.
#[derive(Debug, Clone, Copy)]
pub struct CompletedTurn<'a> {
    /// The turns the call produced, oldest first.
    pub messages: &'a [Message],
    /// What the provider counted the prompt at, when it said.
    pub observed: Option<Usage>,
    /// How many leading messages were left out of the request to make it fit — an index
    /// into the history, exact only because a transcript is appended to.
    pub withheld: usize,
    /// What ended the turn.
    pub stop: TurnStop,
}

#[cfg(test)]
#[path = "session_message_tests.rs"]
mod tests;
