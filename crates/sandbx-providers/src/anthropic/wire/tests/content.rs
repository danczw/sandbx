//! Text, which streams straight through; thinking, which streams *and* accumulates into a
//! replayable block; and the frames that must produce no event rather than ending the
//! turn: pings, unmodeled tags at all three levels, a payload-less heartbeat.

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

/// The deltas and the block both, because they answer to different consumers: a renderer
/// shows the text as it arrives, and only the block can be replayed.
#[tokio::test]
async fn a_signed_thinking_block_is_emitted_whole_at_its_stop() {
    let out = ok_events(vec![
        raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"Let"}}"#),
        raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":" me"}}"#),
        raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":" think"}}"#),
        raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"abc123"}}"#),
        raw(r#"{"type":"content_block_stop","index":0}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;

    assert_eq!(
        out,
        vec![
            AgentEvent::Thinking {
                delta: " me".to_string()
            },
            AgentEvent::Thinking {
                delta: " think".to_string()
            },
            AgentEvent::ThinkingBlock {
                // The `content_block_start` text leads it: a block whose first words
                // arrive on the start frame is one whose replay is short of them.
                text: "Let me think".to_string(),
                signature: "abc123".to_string(),
            },
            stop(StopReason::Unspecified),
        ]
    );
}

/// The default on a Claude 5 model (`display: "omitted"`): an empty text and a real
/// signature, which is the whole of what a replay needs. The text does not decide.
#[tokio::test]
async fn an_empty_thinking_block_is_still_emitted_for_its_signature() {
    let out = ok_events(vec![
        raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}"#),
        raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":""}}"#),
        raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"abc123"}}"#),
        raw(r#"{"type":"content_block_stop","index":0}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;

    assert!(
        out.contains(&AgentEvent::ThinkingBlock {
            text: String::new(),
            signature: "abc123".to_string(),
        }),
        "got {out:?}"
    );
}

/// Dropped, not reported: an unsigned block is rejected on replay, so emitting one would
/// trade this turn's one lost block for a 400 on the next request.
#[tokio::test]
async fn an_unsigned_thinking_block_is_dropped_without_an_error() {
    let out = ok_events(vec![
        raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"unsigned"}}"#),
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
        ],
        "an unsigned block must leave the rest of the turn intact"
    );
}

/// A turn that ends with the block still open: flushing one is how a missing
/// `content_block_stop` is survived, and the signature rule has to hold there too.
#[tokio::test]
async fn a_flushed_thinking_block_obeys_the_same_signature_rule() {
    let signed = ok_events(vec![
        raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"weighing"}}"#),
        raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sig-1"}}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;
    let unsigned = ok_events(vec![
        raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"weighing"}}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;

    assert_eq!(
        signed,
        vec![
            AgentEvent::ThinkingBlock {
                text: "weighing".to_string(),
                signature: "sig-1".to_string(),
            },
            stop(StopReason::Unspecified),
        ]
    );
    assert_eq!(unsigned, vec![stop(StopReason::Unspecified)]);
}

/// No signature and no text to join, so it is whole on arrival and emitted there.
#[tokio::test]
async fn a_redacted_thinking_block_carries_its_opaque_data() {
    let out = ok_events(vec![
        raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"redacted_thinking","data":"EvgBCkgIBR"}}"#),
        raw(r#"{"type":"content_block_stop","index":0}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;

    assert_eq!(
        out,
        vec![
            AgentEvent::RedactedThinking {
                data: "EvgBCkgIBR".to_string()
            },
            stop(StopReason::Unspecified),
        ],
        "the stop must not emit it a second time"
    );
}

/// Reusing an index without closing it. Two block kinds share the map, so a thinking
/// block's deltas could feed a tool call's buffer and either be emitted as the other.
#[tokio::test]
async fn thinking_and_tool_use_do_not_contaminate_one_index() {
    let out = ok_events(vec![
        raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"maybe"}}"#),
        raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sig-1"}}"#),
        raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"ls"}}"#),
        raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"stray"}}"#),
        raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"path\":\".\"}"}}"#),
        raw(r#"{"type":"content_block_stop","index":0}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;

    assert_eq!(
        out,
        vec![
            AgentEvent::Thinking {
                delta: "stray".to_string()
            },
            AgentEvent::ToolCallRequested {
                id: "toolu_1".to_string(),
                name: "ls".to_string(),
                input: serde_json::json!({"path": "."}),
            },
            stop(StopReason::Unspecified),
        ],
        "the abandoned thinking block must not be emitted, nor reach the tool call"
    );
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
