use super::{Content, Message, Role};

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
