//! Public contract of the Messages API request body.
//!
//! Exact wire shape matters here, not just "does it parse": a wrong tag name
//! or an extra field the API doesn't expect fails the real request, and
//! nothing in a type system catches that — only asserting the actual JSON does.

use sandbx_providers::{ContentBlock, MessagesRequest, RequestMessage, Role, ToolDefinition};
use serde_json::json;

#[test]
fn a_minimal_request_serializes_with_no_optional_fields() {
    let request = MessagesRequest {
        model: "claude-opus-5".to_string(),
        max_tokens: 16_000,
        system: None,
        messages: vec![RequestMessage {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "hello".to_string(),
            }],
        }],
        tools: vec![],
    };

    assert_eq!(
        serde_json::to_value(&request).unwrap(),
        json!({
            "model": "claude-opus-5",
            "max_tokens": 16000,
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "hello"}]}
            ],
            "stream": true,
        }),
        "system must be omitted entirely when None, tools when empty"
    );
}

#[test]
fn system_and_tools_are_included_when_present() {
    let request = MessagesRequest {
        model: "claude-opus-5".to_string(),
        max_tokens: 1_000,
        system: Some("Be concise.".to_string()),
        messages: vec![],
        tools: vec![ToolDefinition {
            name: "get_weather".to_string(),
            description: "Get current weather for a location".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {"location": {"type": "string"}},
                "required": ["location"],
            }),
        }],
    };

    let value = serde_json::to_value(&request).unwrap();
    assert_eq!(
        value["stream"],
        json!(true),
        "stream is a constant in the wire shape, not a caller-settable field"
    );
    assert_eq!(value["system"], json!("Be concise."));
    assert_eq!(value["tools"][0]["name"], json!("get_weather"));
    assert_eq!(
        value["tools"][0]["input_schema"]["required"],
        json!(["location"])
    );
}

#[test]
fn roles_serialize_lowercase() {
    let user = RequestMessage {
        role: Role::User,
        content: vec![],
    };
    let assistant = RequestMessage {
        role: Role::Assistant,
        content: vec![],
    };

    assert_eq!(serde_json::to_value(&user).unwrap()["role"], json!("user"));
    assert_eq!(
        serde_json::to_value(&assistant).unwrap()["role"],
        json!("assistant")
    );
}

/// Matches the exact tool_use/tool_result shape the API round-trips in a
/// multi-turn tool call — a wrong tag here breaks every agentic conversation,
/// not just the first turn.
#[test]
fn content_blocks_tag_by_type() {
    let text = ContentBlock::Text {
        text: "hi".to_string(),
    };
    let tool_use = ContentBlock::ToolUse {
        id: "toolu_abc123".to_string(),
        name: "get_weather".to_string(),
        input: json!({"location": "Paris"}),
    };
    let tool_result = ContentBlock::ToolResult {
        tool_use_id: "toolu_abc123".to_string(),
        content: "72F and sunny".to_string(),
        is_error: None,
    };
    let tool_error = ContentBlock::ToolResult {
        tool_use_id: "toolu_abc123".to_string(),
        content: "network unreachable".to_string(),
        is_error: Some(true),
    };

    assert_eq!(
        serde_json::to_value(&text).unwrap(),
        json!({"type": "text", "text": "hi"})
    );
    assert_eq!(
        serde_json::to_value(&tool_use).unwrap(),
        json!({
            "type": "tool_use",
            "id": "toolu_abc123",
            "name": "get_weather",
            "input": {"location": "Paris"},
        })
    );
    assert_eq!(
        serde_json::to_value(&tool_result).unwrap(),
        json!({
            "type": "tool_result",
            "tool_use_id": "toolu_abc123",
            "content": "72F and sunny",
        }),
        "is_error must be omitted, not sent as null, when absent"
    );
    assert_eq!(
        serde_json::to_value(&tool_error).unwrap()["is_error"],
        json!(true)
    );
}
