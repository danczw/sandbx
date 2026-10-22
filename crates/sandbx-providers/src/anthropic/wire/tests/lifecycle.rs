//! How a turn ends: one `Stop` when `message_stop` arrives, an error when it does
//! not, and the fusedness the returned stream promises.

use super::{AgentEvent, ProviderError, StopReason, event_stream, events, ok_events, raw, stop};

#[tokio::test]
async fn message_stop_ends_the_stream_with_a_stop_event() {
    let out = ok_events(vec![raw(r#"{"type":"message_stop"}"#)]).await;

    assert_eq!(
        out,
        vec![stop(StopReason::Unspecified)],
        "message_stop must always produce exactly one Stop"
    );
}

/// `stop_reason` is nullable on the wire, and a truncation must stay distinguishable.
#[tokio::test]
async fn a_null_stop_reason_still_ends_the_turn_with_a_stop() {
    let out = ok_events(vec![
        raw(r#"{"type":"message_delta","delta":{"stop_reason":null},"usage":{"output_tokens":8}}"#),
        raw(r#"{"type":"message_stop"}"#),
    ])
    .await;

    assert_eq!(
        out,
        vec![
            AgentEvent::Usage {
                input_tokens: None,
                output_tokens: Some(8),
                cache_write_tokens: None,
                cache_read_tokens: None,
            },
            stop(StopReason::Unspecified),
        ]
    );
}

/// A connection dropping between `message_delta` and `message_stop` is a truncated
/// turn, not a clean finish.
#[tokio::test]
async fn a_stop_reason_without_message_stop_truncates() {
    let out = events(vec![raw(
        r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":8}}"#,
    )])
    .await;

    assert!(matches!(out[0], Ok(AgentEvent::Usage { .. })));
    assert!(
        matches!(out[1], Err(ProviderError::StreamEndedUnexpectedly)),
        "expected the missing message_stop to be reported"
    );
    assert_eq!(out.len(), 2, "no Stop may be fabricated for a lost turn");
}

#[tokio::test]
async fn connection_closing_before_message_stop_is_reported() {
    let out = events(vec![raw(r#"{"type":"ping"}"#)]).await;

    assert_eq!(out.len(), 1);
    assert!(matches!(
        out[0],
        Err(ProviderError::StreamEndedUnexpectedly)
    ));
}

#[tokio::test]
async fn an_in_band_error_event_ends_the_stream() {
    let out = events(vec![
        raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#),
        raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"partial"}}"#),
        raw(r#"{"type":"error","error":{"type":"overloaded_error","message":"overloaded"}}"#),
    ])
    .await;

    assert_eq!(out.len(), 2);
    assert!(out[0].is_ok());
    match &out[1] {
        Err(ProviderError::ApiError { status, kind, .. }) => {
            assert_eq!(*status, None);
            assert_eq!(kind, "overloaded_error");
        }
        other => panic!("expected ApiError, got {other:?}"),
    }
}

/// `unfold` panics if polled past `None`, and callers may over-poll.
#[tokio::test]
async fn the_stream_is_fused_and_survives_being_over_polled() {
    use futures_util::StreamExt;

    // Boxed to poll by hand: the stream holds `next_agent_event`'s async body and so
    // is not `Unpin`, which `.next()` requires.
    let mut stream = Box::pin(event_stream(futures_util::stream::iter(vec![raw(
        r#"{"type":"message_stop"}"#,
    )])));

    assert!(stream.next().await.is_some());
    assert!(stream.next().await.is_none());
    assert!(
        stream.next().await.is_none(),
        "polling once past the end must not panic"
    );
    assert!(futures_util::stream::FusedStream::is_terminated(&stream));
}
