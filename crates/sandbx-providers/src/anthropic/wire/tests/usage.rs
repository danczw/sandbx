//! Token accounting: one `Usage` per turn, carrying the last cumulative figure the
//! API reported for each counter.

use super::{AgentEvent, ProviderError, StopReason, events, ok_events, raw, stop};

#[tokio::test]
async fn start_and_delta_combine_into_one_usage_event() {
    let out = ok_events(vec![
        raw(r#"{"type":"message_start","message":{"usage":{"input_tokens":10}}}"#),
        raw(r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;

    assert_eq!(
        out,
        vec![
            AgentEvent::Usage {
                input_tokens: Some(10),
                output_tokens: Some(5),
                cache_write_tokens: None,
                cache_read_tokens: None,
            },
            stop(StopReason::EndTurn),
        ]
    );
}

/// Server-side tool use inflates `input_tokens` mid-stream, so the cumulative
/// `message_delta` figures must win.
#[tokio::test]
async fn a_delta_restating_input_tokens_wins_over_start() {
    let out = ok_events(vec![
        raw(r#"{"type":"message_start","message":{"usage":{"input_tokens":2679,"cache_read_input_tokens":0}}}"#),
        raw(r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"input_tokens":10682,"cache_creation_input_tokens":0,"cache_read_input_tokens":4,"output_tokens":510}}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;

    assert_eq!(
        out[0],
        AgentEvent::Usage {
            input_tokens: Some(10682),
            output_tokens: Some(510),
            cache_write_tokens: Some(0),
            cache_read_tokens: Some(4),
        }
    );
}

/// Several `message_delta` events each restate the totals, so a consumer summing one
/// `Usage` per frame would overcount.
#[tokio::test]
async fn several_deltas_produce_exactly_one_usage_event() {
    let out = ok_events(vec![
        raw(r#"{"type":"message_start","message":{"usage":{"input_tokens":10}}}"#),
        raw(r#"{"type":"message_delta","delta":{"stop_reason":null},"usage":{"output_tokens":5}}"#),
        raw(r#"{"type":"message_delta","delta":{"stop_reason":null},"usage":{"output_tokens":9}}"#),
        raw(r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":12}}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;

    assert_eq!(
        out,
        vec![
            AgentEvent::Usage {
                input_tokens: Some(10),
                output_tokens: Some(12),
                cache_write_tokens: None,
                cache_read_tokens: None,
            },
            stop(StopReason::EndTurn),
        ],
        "the last cumulative figure, reported once"
    );
}

#[tokio::test]
async fn a_turn_with_no_usage_reported_emits_no_usage_event() {
    let out = ok_events(vec![
        raw(r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"}}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;

    assert_eq!(out, vec![stop(StopReason::EndTurn)]);
}

/// Both frames really ship without a `usage` key, and neither is worth ending a turn.
#[tokio::test]
async fn a_frame_with_no_usage_field_does_not_end_the_turn() {
    let out = ok_events(vec![
        raw(r#"{"type":"message_start","message":{}}"#),
        raw(
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
        ),
        raw(
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}"#,
        ),
        raw(r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"}}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;

    assert_eq!(
        out,
        vec![
            AgentEvent::Text {
                delta: "hi".to_string()
            },
            stop(StopReason::EndTurn),
        ]
    );
}

/// Token counts are reported even when the turn is lost — they were billed.
#[tokio::test]
async fn usage_survives_a_truncated_turn() {
    let out = events(vec![raw(
        r#"{"type":"message_delta","delta":{"stop_reason":null},"usage":{"output_tokens":8}}"#,
    )])
    .await;

    assert!(matches!(out[0], Ok(AgentEvent::Usage { .. })));
    assert!(matches!(
        out[1],
        Err(ProviderError::StreamEndedUnexpectedly)
    ));
}
