//! A [`Prompt`] in the shape `POST /v1/messages` wants.
//!
//! Every wire field name, every omission rule and the `stream` constant live here
//! and nowhere else — this module is the whole of what [`crate::prompt`] refuses to
//! know. Hand-written rather than derived, because several rules are conditional and
//! `serde`'s attributes cannot express them.

use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Serialize, Serializer};

use crate::prompt::{
    ContentBlock, Prompt, RequestMessage, Role, Thinking, ToolChoice, ToolDefinition,
};

pub(super) struct Body<'a>(pub(super) &'a Prompt);

impl Serialize for Body<'_> {
    /// The destructuring `let` makes a field added to [`Prompt`] later fail to
    /// compile until it is written out here.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Prompt {
            model,
            max_output_tokens,
            system,
            messages,
            tools,
            tool_choice,
            thinking,
        } = self.0;

        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("model", model)?;
        map.serialize_entry("max_tokens", max_output_tokens)?;
        // Omitted, not `null`: the API rejects a null `system`, and an empty `tools`
        // alongside replayed `tool_use` blocks.
        if let Some(system) = system {
            map.serialize_entry("system", system)?;
        }
        map.serialize_entry("messages", &Messages(messages))?;
        if !tools.is_empty() {
            map.serialize_entry("tools", &Tools(tools))?;
        }
        // Only alongside `tools`: the API rejects a choice over tools that were not
        // defined, so an empty list with a choice set is a request it refuses.
        if let Some(tool_choice) = tool_choice.filter(|_| !tools.is_empty()) {
            map.serialize_entry("tool_choice", &ToolChoiceBody(tool_choice))?;
        }
        if let Some(thinking) = thinking {
            map.serialize_entry("thinking", &ThinkingBody(*thinking))?;
        }
        // Not a `Prompt` field: this client has no non-streaming path.
        map.serialize_entry("stream", &true)?;
        map.end()
    }
}

struct Messages<'a>(&'a [RequestMessage]);

impl Serialize for Messages<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for message in self.0 {
            seq.serialize_element(&MessageBody(message))?;
        }
        seq.end()
    }
}

struct MessageBody<'a>(&'a RequestMessage);

impl Serialize for MessageBody<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let RequestMessage { role, content } = self.0;
        let role = match role {
            Role::User => "user",
            Role::Assistant => "assistant",
        };

        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("role", role)?;
        map.serialize_entry("content", &Blocks(content))?;
        map.end()
    }
}

struct Blocks<'a>(&'a [ContentBlock]);

impl Serialize for Blocks<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for block in self.0 {
            seq.serialize_element(&BlockBody(block))?;
        }
        seq.end()
    }
}

struct BlockBody<'a>(&'a ContentBlock);

impl Serialize for BlockBody<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        match self.0 {
            ContentBlock::Text { text } => {
                map.serialize_entry("type", "text")?;
                map.serialize_entry("text", text)?;
            }
            ContentBlock::Thinking { text, signature } => {
                map.serialize_entry("type", "thinking")?;
                // The text's wire name is `thinking`, not `text`, and the signature
                // is not optional: the API rejects a thinking block missing either.
                map.serialize_entry("thinking", text)?;
                map.serialize_entry("signature", signature)?;
            }
            ContentBlock::RedactedThinking { data } => {
                map.serialize_entry("type", "redacted_thinking")?;
                map.serialize_entry("data", data)?;
            }
            ContentBlock::ToolUse { id, name, input } => {
                map.serialize_entry("type", "tool_use")?;
                map.serialize_entry("id", id)?;
                map.serialize_entry("name", name)?;
                map.serialize_entry("input", input)?;
            }
            ContentBlock::ToolResult {
                tool_use_id,
                content,
                is_error,
            } => {
                map.serialize_entry("type", "tool_result")?;
                map.serialize_entry("tool_use_id", tool_use_id)?;
                map.serialize_entry("content", content)?;
                if let Some(is_error) = is_error {
                    map.serialize_entry("is_error", is_error)?;
                }
            }
        }
        map.end()
    }
}

struct Tools<'a>(&'a [ToolDefinition]);

impl Serialize for Tools<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for tool in self.0 {
            seq.serialize_element(&ToolBody(tool))?;
        }
        seq.end()
    }
}

struct ToolBody<'a>(&'a ToolDefinition);

impl Serialize for ToolBody<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let ToolDefinition {
            name,
            description,
            schema,
        } = self.0;

        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("name", name)?;
        map.serialize_entry("description", description)?;
        map.serialize_entry("input_schema", schema)?;
        map.end()
    }
}

struct ToolChoiceBody(ToolChoice);

impl Serialize for ToolChoiceBody {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let kind = match self.0 {
            ToolChoice::None => "none",
        };

        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("type", kind)?;
        map.end()
    }
}

struct ThinkingBody(Thinking);

impl Serialize for ThinkingBody {
    /// `type: "adaptive"`, never the `enabled`/`budget_tokens` form: that one is
    /// deprecated on Claude 4.6 and a 400 on 4.7 and every Claude 5 model.
    ///
    /// `display` governs only whether the summary text comes back. Blocks are billed
    /// and replayed the same either way, so the replay path does not depend on this.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let display = match self.0 {
            Thinking::Visible => "summarized",
        };

        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("type", "adaptive")?;
        map.serialize_entry("display", display)?;
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prompt() -> Prompt {
        Prompt {
            model: "claude-sonnet-5".to_string(),
            max_output_tokens: 1024,
            system: None,
            messages: vec![RequestMessage {
                role: Role::User,
                content: vec![ContentBlock::Text {
                    text: "hello".to_string(),
                }],
            }],
            tools: Vec::new(),
            tool_choice: None,
            thinking: None,
        }
    }

    fn body(prompt: &Prompt) -> serde_json::Value {
        serde_json::to_value(Body(prompt)).expect("the body serializes")
    }

    fn tool() -> ToolDefinition {
        ToolDefinition {
            name: "read".to_string(),
            description: "Read a file".to_string(),
            schema: serde_json::json!({"type": "object"}),
        }
    }

    #[test]
    fn a_minimal_prompt_carries_only_the_required_keys() {
        assert_eq!(
            body(&prompt()),
            serde_json::json!({
                "model": "claude-sonnet-5",
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": [{"type": "text", "text": "hello"}]}],
                "stream": true,
            })
        );
    }

    #[test]
    fn max_output_tokens_is_sent_as_max_tokens() {
        let body = body(&prompt());
        assert_eq!(body["max_tokens"], 1024);
        assert!(body.get("max_output_tokens").is_none());
    }

    #[test]
    fn streaming_is_always_on() {
        assert_eq!(body(&prompt())["stream"], true);
    }

    #[test]
    fn an_absent_system_prompt_is_omitted_not_null() {
        let body = body(&prompt());
        assert!(body.get("system").is_none(), "{body}");
    }

    #[test]
    fn a_present_system_prompt_is_sent() {
        let prompt = Prompt {
            system: Some("be brief".to_string()),
            ..prompt()
        };
        assert_eq!(body(&prompt)["system"], "be brief");
    }

    #[test]
    fn an_empty_tool_list_is_omitted_not_an_empty_array() {
        let body = body(&prompt());
        assert!(body.get("tools").is_none(), "{body}");
    }

    #[test]
    fn a_tool_schema_is_sent_as_input_schema() {
        let prompt = Prompt {
            tools: vec![tool()],
            ..prompt()
        };
        let body = body(&prompt);
        assert_eq!(body["tools"][0]["name"], "read");
        assert_eq!(body["tools"][0]["description"], "Read a file");
        assert_eq!(
            body["tools"][0]["input_schema"],
            serde_json::json!({"type": "object"})
        );
        assert!(body["tools"][0].get("schema").is_none(), "{body}");
    }

    #[test]
    fn a_tool_choice_without_tools_is_dropped() {
        let prompt = Prompt {
            tool_choice: Some(ToolChoice::None),
            ..prompt()
        };
        let body = body(&prompt);
        assert!(body.get("tool_choice").is_none(), "{body}");
    }

    #[test]
    fn a_tool_choice_alongside_tools_is_sent() {
        let prompt = Prompt {
            tools: vec![tool()],
            tool_choice: Some(ToolChoice::None),
            ..prompt()
        };
        assert_eq!(
            body(&prompt)["tool_choice"],
            serde_json::json!({"type": "none"})
        );
    }

    #[test]
    fn absent_thinking_sends_no_thinking_object() {
        let body = body(&prompt());
        assert!(body.get("thinking").is_none(), "{body}");
    }

    #[test]
    fn visible_thinking_asks_for_an_adaptive_summary() {
        let prompt = Prompt {
            thinking: Some(Thinking::Visible),
            ..prompt()
        };
        assert_eq!(
            body(&prompt)["thinking"],
            serde_json::json!({"type": "adaptive", "display": "summarized"})
        );
    }

    #[test]
    fn budget_tokens_is_never_sent() {
        let prompt = Prompt {
            thinking: Some(Thinking::Visible),
            ..prompt()
        };
        let body = body(&prompt);
        assert!(body["thinking"].get("budget_tokens").is_none(), "{body}");
        assert_ne!(body["thinking"]["type"], "enabled");
    }

    #[test]
    fn a_thinking_block_replays_its_text_under_the_thinking_key() {
        let prompt = Prompt {
            messages: vec![RequestMessage {
                role: Role::Assistant,
                content: vec![ContentBlock::Thinking {
                    text: "step one".to_string(),
                    signature: "sig".to_string(),
                }],
            }],
            ..prompt()
        };
        assert_eq!(
            body(&prompt)["messages"][0]["content"][0],
            serde_json::json!({
                "type": "thinking",
                "thinking": "step one",
                "signature": "sig",
            })
        );
    }

    #[test]
    fn a_redacted_thinking_block_replays_its_opaque_data() {
        let prompt = Prompt {
            messages: vec![RequestMessage {
                role: Role::Assistant,
                content: vec![ContentBlock::RedactedThinking {
                    data: "opaque".to_string(),
                }],
            }],
            ..prompt()
        };
        assert_eq!(
            body(&prompt)["messages"][0]["content"][0],
            serde_json::json!({"type": "redacted_thinking", "data": "opaque"})
        );
    }

    #[test]
    fn a_tool_use_block_replays_its_input_verbatim() {
        let prompt = Prompt {
            messages: vec![RequestMessage {
                role: Role::Assistant,
                content: vec![ContentBlock::ToolUse {
                    id: "call_1".to_string(),
                    name: "read".to_string(),
                    input: serde_json::json!({"path": "a.txt"}),
                }],
            }],
            ..prompt()
        };
        assert_eq!(
            body(&prompt)["messages"][0]["content"][0],
            serde_json::json!({
                "type": "tool_use",
                "id": "call_1",
                "name": "read",
                "input": {"path": "a.txt"},
            })
        );
    }

    #[test]
    fn a_successful_tool_result_omits_is_error() {
        let prompt = Prompt {
            messages: vec![RequestMessage {
                role: Role::User,
                content: vec![ContentBlock::ToolResult {
                    tool_use_id: "call_1".to_string(),
                    content: "ok".to_string(),
                    is_error: None,
                }],
            }],
            ..prompt()
        };
        assert_eq!(
            body(&prompt)["messages"][0]["content"][0],
            serde_json::json!({
                "type": "tool_result",
                "tool_use_id": "call_1",
                "content": "ok",
            })
        );
    }

    #[test]
    fn a_failed_tool_result_marks_is_error() {
        let prompt = Prompt {
            messages: vec![RequestMessage {
                role: Role::User,
                content: vec![ContentBlock::ToolResult {
                    tool_use_id: "call_1".to_string(),
                    content: "boom".to_string(),
                    is_error: Some(true),
                }],
            }],
            ..prompt()
        };
        assert_eq!(body(&prompt)["messages"][0]["content"][0]["is_error"], true);
    }

    #[test]
    fn an_assistant_role_is_sent_lowercase() {
        let prompt = Prompt {
            messages: vec![RequestMessage {
                role: Role::Assistant,
                content: Vec::new(),
            }],
            ..prompt()
        };
        assert_eq!(body(&prompt)["messages"][0]["role"], "assistant");
    }
}
