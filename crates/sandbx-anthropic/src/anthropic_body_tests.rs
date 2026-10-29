use super::Body;
use sandbx_prompt::{
    ContentBlock, Prompt, RequestMessage, Role, Thinking, ToolChoice, ToolDefinition,
};

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
