//! What a transcript line holds: one turn of the conversation, and what the request for it
//! cost. Mirrors `sandbx_providers`'s `RequestMessage`, `Role` and `ContentBlock`, and
//! `sandbx_agent`'s `PromptUsage`, declared again so this crate depends on no other;
//! `sandbx-cli` translates, and fails to compile on a new block kind.

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

/// One turn's worth of everything a transcript records; the three travel together
/// because threading two leaves accounting that describes a different conversation.
#[derive(Debug, Clone, Copy)]
pub struct CompletedTurn<'a> {
    /// The turns the call produced, oldest first.
    pub messages: &'a [Message],
    /// What the provider counted the prompt at, when it said.
    pub observed: Option<Usage>,
    /// How many leading messages were left out of the request to make it fit — an index
    /// into the history, exact only because a transcript is appended to.
    pub withheld: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_line_is_the_shape_the_api_takes() {
        let message = Message {
            role: Role::Assistant,
            content: vec![Content::ToolUse {
                id: "toolu_01".to_owned(),
                name: "ls".to_owned(),
                input: serde_json::json!({ "path": "/srv" }),
            }],
        };

        assert_eq!(
            serde_json::to_value(&message).unwrap(),
            serde_json::json!({
                "role": "assistant",
                "content": [{
                    "type": "tool_use",
                    "id": "toolu_01",
                    "name": "ls",
                    "input": { "path": "/srv" },
                }],
            })
        );
    }

    #[test]
    fn an_absent_is_error_reads_back_as_none() {
        let line = serde_json::json!({
            "role": "user",
            "content": [{
                "type": "tool_result",
                "tool_use_id": "toolu_01",
                "content": "bin  etc",
            }],
        });

        let message: Message = serde_json::from_value(line.clone()).unwrap();

        assert_eq!(
            message.content,
            vec![Content::ToolResult {
                tool_use_id: "toolu_01".to_owned(),
                content: "bin  etc".to_owned(),
                is_error: None,
            }]
        );
        assert_eq!(serde_json::to_value(&message).unwrap(), line);
    }

    #[test]
    fn an_unknown_field_is_ignored_rather_than_refused() {
        let line = serde_json::json!({
            "role": "assistant",
            "content": [{ "type": "text", "text": "hi", "citations": [] }],
            "thinking_signature": "abc",
        });

        let message: Message = serde_json::from_value(line).unwrap();

        assert_eq!(
            message.content,
            vec![Content::Text {
                text: "hi".to_owned()
            }]
        );
    }
}
