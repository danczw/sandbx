//! Tool-call accumulation: the one block kind whose deltas have to be buffered before
//! they mean anything, and the ways a stream can leave that buffer in an odd state.

use super::{AgentEvent, ProviderError, StopReason, events, ok_events, raw, stop};

#[tokio::test]
async fn a_call_split_across_fragments_becomes_one_event() {
    let out = ok_events(vec![
        raw(r#"{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_01A","name":"get_weather"}}"#),
        raw(r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"loc"}}"#),
        raw(r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"ation\":\"Pa"}}"#),
        raw(r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"ris\"}"}}"#),
        raw(r#"{"type":"content_block_stop","index":1}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;

    assert_eq!(
        out,
        vec![
            AgentEvent::ToolCallRequested {
                id: "toolu_01A".to_string(),
                name: "get_weather".to_string(),
                input: serde_json::json!({"location": "Paris"}),
            },
            stop(StopReason::Unspecified),
        ],
        "expected exactly one tool event, only after every fragment arrived"
    );
}

/// A tool taking no arguments sends no `input_json_delta`, so the buffer is empty at
/// `content_block_stop` and `{}` is the input — and the API rejects the next request
/// for an unanswered `tool_use`.
#[tokio::test]
async fn a_zero_argument_tool_call_yields_an_empty_input() {
    let out = ok_events(vec![
        raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_01A","name":"get_time"}}"#),
        raw(r#"{"type":"content_block_stop","index":0}"#),
        raw(r#"{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":3}}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;

    assert_eq!(
        out[0],
        AgentEvent::ToolCallRequested {
            id: "toolu_01A".to_string(),
            name: "get_time".to_string(),
            input: serde_json::json!({}),
        }
    );
    assert_eq!(out.last(), Some(&stop(StopReason::ToolUse)));
}

/// The same call, with the empty-string delta the API sends instead on some turns.
#[tokio::test]
async fn an_empty_input_json_delta_is_also_an_empty_input() {
    let out = ok_events(vec![
        raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_01A","name":"get_time"}}"#),
        raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":""}}"#),
        raw(r#"{"type":"content_block_stop","index":0}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;

    assert_eq!(
        out[0],
        AgentEvent::ToolCallRequested {
            id: "toolu_01A".to_string(),
            name: "get_time".to_string(),
            input: serde_json::json!({}),
        }
    );
}

#[tokio::test]
async fn parallel_calls_accumulate_independently_by_index() {
    let out = ok_events(vec![
        raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_A","name":"get_weather"}}"#),
        raw(r#"{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_B","name":"get_time"}}"#),
        raw(r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"tz\":\"UTC\"}"}}"#),
        raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"location\":\"NYC\"}"}}"#),
        raw(r#"{"type":"content_block_stop","index":1}"#),
        raw(r#"{"type":"content_block_stop","index":0}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;

    assert_eq!(
        out,
        vec![
            AgentEvent::ToolCallRequested {
                id: "toolu_B".to_string(),
                name: "get_time".to_string(),
                input: serde_json::json!({"tz": "UTC"}),
            },
            AgentEvent::ToolCallRequested {
                id: "toolu_A".to_string(),
                name: "get_weather".to_string(),
                input: serde_json::json!({"location": "NYC"}),
            },
            stop(StopReason::Unspecified),
        ]
    );
}

/// Dropping a block whose `content_block_stop` was lost, while still reporting
/// `Stop { ToolUse }`, would tell the caller to run a tool it was never given.
#[tokio::test]
async fn a_block_left_open_is_flushed_at_message_stop() {
    let out = ok_events(vec![
        raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_A","name":"get_weather"}}"#),
        raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"location\":\"NYC\"}"}}"#),
        raw(r#"{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":8}}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;

    assert_eq!(
        out.first(),
        Some(&AgentEvent::ToolCallRequested {
            id: "toolu_A".to_string(),
            name: "get_weather".to_string(),
            input: serde_json::json!({"location": "NYC"}),
        })
    );
    assert_eq!(out.last(), Some(&stop(StopReason::ToolUse)));
}

/// A new block's deltas landing in an abandoned tool call would emit a
/// `ToolCallRequested` the model never asked for, which the agent loop would run.
#[tokio::test]
async fn a_block_opened_over_an_unclosed_one_discards_it() {
    let out = events(vec![
        raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_A","name":"bash"}}"#),
        raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#),
        raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"rm -rf /\"}"}}"#),
        raw(r#"{"type":"content_block_stop","index":0}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;

    assert!(
        !out.iter()
            .any(|event| matches!(event, Ok(AgentEvent::ToolCallRequested { .. }))),
        "a tool call was fabricated from a text block's deltas: {out:?}"
    );
}

#[tokio::test]
async fn unparseable_json_is_a_malformed_event_not_a_panic() {
    let out = events(vec![
        raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_X","name":"broken"}}"#),
        raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"not json"}}"#),
        raw(r#"{"type":"content_block_stop","index":0}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;

    assert!(matches!(out[0], Err(ProviderError::MalformedEvent { .. })));
    // Unlike a frame that fails to parse, one unusable tool call does not end the
    // turn: the `message_stop` behind it is still honoured.
    assert!(matches!(out[1], Ok(AgentEvent::Stop { .. })));
}
