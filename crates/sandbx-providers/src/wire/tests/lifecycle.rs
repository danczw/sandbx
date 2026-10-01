//! How a turn ends: exactly one `Stop` when `message_stop` arrives, an error
//! when it does not, and the fusedness the returned stream promises.

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

/// `stop_reason` is nullable on the wire. The turn still ended, and the
/// caller still has to be able to tell that apart from a truncated stream —
/// so a `Stop` is emitted either way.
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
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            stop(StopReason::Unspecified),
        ]
    );
}

/// A stop reason arriving before `message_stop` is held, not emitted: the
/// stream ending is what ends the turn, so a connection that drops between
/// the two is still reported as truncated rather than as a clean finish.
#[tokio::test]
async fn a_stop_reason_without_message_stop_is_still_a_truncated_turn() {
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
    // No message_stop before the underlying stream ends.
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

/// `unfold` panics outright if polled after it returns `None`, and this
/// stream is handed to callers who may poll it once more — a `select!` arm
/// that does not break on `None`, a stray `.next()` after a `while let`.
/// Being fused is part of the contract, not an implementation detail.
#[tokio::test]
async fn the_stream_is_fused_and_survives_being_over_polled() {
    use futures_util::StreamExt;

    // Boxed only to poll it by hand: the stream holds the async body of
    // `next_agent_event` and so is not `Unpin`, which `.collect()` (taking
    // `self`) hides from every other test here but `.next()` does not.
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
