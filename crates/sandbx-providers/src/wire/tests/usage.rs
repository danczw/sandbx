//! Token accounting: one `Usage` event per turn, carrying the last cumulative
//! figure the API reported for each counter.

use super::{AgentEvent, ProviderError, StopReason, events, ok_events, raw, stop};

#[tokio::test]
async fn message_start_and_message_delta_combine_into_one_usage_event() {
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
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            stop(StopReason::EndTurn),
        ]
    );
}

/// The docs call the `message_delta` counts cumulative, and server-side tool
/// use inflates `input_tokens` mid-stream — Anthropic's own web-search
/// example jumps from 2679 to 10682. The delta's figures must win, or the
/// turn is billed at a fraction of what it cost.
#[tokio::test]
async fn a_message_delta_restating_input_tokens_wins_over_message_start() {
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
            cache_creation_input_tokens: Some(0),
            cache_read_input_tokens: Some(4),
        }
    );
}

/// "One or more" `message_delta` events are documented, and the counts in
/// each restate the totals. Exactly one `Usage` event must come out, or a
/// consumer adding them up reports several times the real spend.
#[tokio::test]
async fn several_message_deltas_produce_exactly_one_usage_event() {
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
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            stop(StopReason::EndTurn),
        ],
        "the last cumulative figure, reported once"
    );
}

/// A turn that never reported a count emits no `Usage` at all, rather than
/// one claiming a genuine zero.
#[tokio::test]
async fn a_turn_with_no_usage_reported_emits_no_usage_event() {
    let out = ok_events(vec![
        raw(r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"}}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;

    assert_eq!(out, vec![stop(StopReason::EndTurn)]);
}

/// A `message_delta` with no `usage` key, and a `message_start` with no
/// `usage` key — the latter is the shape the docs' extended-thinking example
/// shows. Neither is worth ending a paid turn over.
#[tokio::test]
async fn frames_missing_their_usage_field_do_not_end_the_turn() {
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
