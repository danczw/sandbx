//! Public contract of the Messages API request body.
//!
//! The exact wire shape, not just that it parses: a wrong tag name or an extra field
//! fails the real request, and no type system catches that.

use sandbx_providers::{
    ContentBlock, MessagesRequest, RequestMessage, Role, ToolChoice, ToolDefinition,
};
use serde_json::json;

/// One tool, so a request has something a `tool_choice` can be a choice over.
fn a_tool() -> ToolDefinition {
    ToolDefinition {
        name: "get_weather".to_string(),
        description: "Get current weather for a location".to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {"location": {"type": "string"}},
            "required": ["location"],
        }),
    }
}

#[test]
fn a_minimal_request_omits_every_optional_field() {
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
        tool_choice: None,
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
        "system and tool_choice must be omitted entirely when None, tools when empty"
    );
}

#[test]
fn system_and_tools_are_included_when_present() {
    let request = MessagesRequest {
        model: "claude-opus-5".to_string(),
        max_tokens: 1_000,
        system: Some("Be concise.".to_string()),
        messages: vec![],
        tools: vec![a_tool()],
        tool_choice: None,
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
    assert_eq!(value.get("tool_choice"), None, "a None choice was sent");
}

/// The shape a wrap-up round sends: the tools stay, and the choice forbids calling one.
#[test]
fn a_tool_choice_rides_alongside_the_tools_it_names() {
    let request = MessagesRequest {
        model: "claude-opus-5".to_string(),
        max_tokens: 1_000,
        system: None,
        messages: vec![],
        tools: vec![a_tool()],
        tool_choice: Some(ToolChoice::None),
    };

    let value = serde_json::to_value(&request).unwrap();
    assert_eq!(value["tool_choice"], json!({"type": "none"}));
    assert_eq!(value["tools"][0]["name"], json!("get_weather"));
}

/// The API refuses a choice over tools no request defined, so it is not sent.
#[test]
fn a_tool_choice_without_tools_is_dropped() {
    let request = MessagesRequest {
        model: "claude-opus-5".to_string(),
        max_tokens: 1_000,
        system: None,
        messages: vec![],
        tools: vec![],
        tool_choice: Some(ToolChoice::None),
    };

    let value = serde_json::to_value(&request).unwrap();
    assert_eq!(value.get("tool_choice"), None, "got {value}");
    assert_eq!(value.get("tools"), None);
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

/// The exact tool_use/tool_result shape the API round-trips in a multi-turn tool call.
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
