//! Text and thinking blocks, which stream straight through, and the frames that must
//! produce no event rather than ending the turn: pings, unmodeled tags at all three
//! levels, a payload-less heartbeat.

use super::{AgentEvent, StopReason, ok_events, raw, stop};

#[tokio::test]
async fn text_deltas_stream_immediately() {
    let out = ok_events(vec![
        raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#),
        raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hel"}}"#),
        raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"lo"}}"#),
        raw(r#"{"type":"content_block_stop","index":0}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;

    assert_eq!(
        out,
        vec![
            AgentEvent::Text {
                delta: "Hel".to_string()
            },
            AgentEvent::Text {
                delta: "lo".to_string()
            },
            stop(StopReason::Unspecified),
        ]
    );
}

#[tokio::test]
async fn thinking_deltas_stream_immediately() {
    let out = ok_events(vec![
        raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}"#),
        raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"Let me"}}"#),
        raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":" think"}}"#),
        raw(r#"{"type":"content_block_stop","index":0}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;

    assert_eq!(
        out,
        vec![
            AgentEvent::Thinking {
                delta: "Let me".to_string()
            },
            AgentEvent::Thinking {
                delta: " think".to_string()
            },
            stop(StopReason::Unspecified),
        ]
    );
}

/// A `signature_delta` accompanies a thinking block and has nowhere to go in
/// `AgentEvent`, so it is consumed rather than failing to parse.
#[tokio::test]
async fn signature_delta_is_accepted_and_produces_no_event() {
    let out = ok_events(vec![
        raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}"#),
        raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"abc123"}}"#),
        raw(r#"{"type":"content_block_stop","index":0}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;

    assert_eq!(out, vec![stop(StopReason::Unspecified)]);
}

#[tokio::test]
async fn ping_produces_no_event() {
    let out = ok_events(vec![
        raw(r#"{"type":"ping"}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;

    assert_eq!(out, vec![stop(StopReason::Unspecified)]);
}

#[tokio::test]
async fn an_unknown_event_type_is_ignored_not_fatal() {
    let out = ok_events(vec![
        raw(r#"{"type":"some_future_event","whatever":{"nested":true}}"#),
        raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#),
        raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"still here"}}"#),
        raw(r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":2}}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;

    assert_eq!(
        out.first(),
        Some(&AgentEvent::Text {
            delta: "still here".to_string()
        }),
        "an unknown event type discarded the rest of the turn"
    );
    assert_eq!(out.last(), Some(&stop(StopReason::EndTurn)));
}

#[tokio::test]
async fn an_unknown_block_or_delta_is_ignored_not_fatal() {
    let out = ok_events(vec![
        raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"server_tool_use","id":"srvtoolu_1","name":"web_search"}}"#),
        raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"citations_delta","citation":{"url":"https://example.com"}}}"#),
        raw(r#"{"type":"content_block_stop","index":0}"#),
        raw(r#"{"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}"#),
        raw(r#"{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"answer"}}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;

    assert_eq!(
        out,
        vec![
            AgentEvent::Text {
                delta: "answer".to_string()
            },
            stop(StopReason::Unspecified),
        ]
    );
}

#[tokio::test]
async fn a_frame_with_no_payload_does_not_end_the_turn() {
    let out = ok_events(vec![
        raw(r#"{"type":"message_start","message":{"usage":{"input_tokens":10}}}"#),
        raw(""),
        raw("   "),
        raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#),
        raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"survived"}}"#),
        raw(r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":1}}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;

    assert_eq!(
        out.first(),
        Some(&AgentEvent::Text {
            delta: "survived".to_string()
        }),
        "a payload-less heartbeat frame ended the turn"
    );
    assert_eq!(out.last(), Some(&stop(StopReason::EndTurn)));
}
