use bytes::Bytes;
use futures_util::{StreamExt, stream};
use sandbx_provider::ProviderError;

use super::{MAX_EVENT_BYTES, tokenize};

async fn tokenize_all(chunks: Vec<&'static [u8]>) -> Vec<Result<String, ProviderError>> {
    let byte_stream = stream::iter(chunks.into_iter().map(|c| Ok(Bytes::from_static(c))));
    tokenize(byte_stream).collect().await
}

#[tokio::test]
async fn a_single_event_in_one_chunk() {
    let events = tokenize_all(vec![b"event: ping\ndata: {}\n\n"]).await;

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].as_ref().unwrap(), "{}");
}

#[tokio::test]
async fn an_event_split_across_chunks() {
    let events = tokenize_all(vec![b"event: ping\nda", b"ta: {}\n\n"]).await;

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].as_ref().unwrap(), "{}");
}

#[tokio::test]
async fn blank_keep_alive_lines_are_ignored() {
    let events = tokenize_all(vec![b"\n\nevent: ping\ndata: {}\n\n"]).await;

    assert_eq!(
        events.len(),
        1,
        "leading blank lines produced a phantom event"
    );
}

#[tokio::test]
async fn multi_line_data_is_joined_with_newlines() {
    let events = tokenize_all(vec![b"data: line one\ndata: line two\n\n"]).await;

    assert_eq!(events[0].as_ref().unwrap(), "line one\nline two");
}

#[tokio::test]
async fn non_utf8_bytes_are_reported_not_panicked_on() {
    let events = tokenize_all(vec![b"data: \xff\xfe\n\n"]).await;

    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0],
        Err(ProviderError::MalformedEvent { .. })
    ));
}

#[tokio::test]
async fn a_trailing_event_with_no_blank_line_survives() {
    let events = tokenize_all(vec![b"event: message_stop\ndata: {}"]).await;

    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].as_ref().unwrap(),
        "{}",
        "the unterminated final line was dropped"
    );
}

/// The shape a connection reset produces: the last chunk ends mid-line.
#[tokio::test]
async fn an_unterminated_line_split_across_chunks_survives() {
    let events = tokenize_all(vec![b"data: {\"ty", b"pe\":\"message_stop\"}"]).await;

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].as_ref().unwrap(), "{\"type\":\"message_stop\"}");
}

#[tokio::test]
async fn id_and_comment_lines_are_ignored() {
    let events = tokenize_all(vec![b": keep-alive comment\nid: 5\ndata: {}\n\n"]).await;

    assert_eq!(events[0].as_ref().unwrap(), "{}");
}

/// A CDN or proxy heartbeat: still a frame, for the vendor's accumulator to skip.
#[tokio::test]
async fn a_comment_only_frame_yields_an_empty_payload() {
    let events = tokenize_all(vec![b": keep-alive\n\ndata: {}\n\n"]).await;

    assert_eq!(events.len(), 2);
    assert_eq!(events[0].as_ref().unwrap(), "");
    assert_eq!(events[1].as_ref().unwrap(), "{}");
}

#[tokio::test]
async fn an_event_larger_than_the_cap_is_rejected() {
    let huge: &'static [u8] = Box::leak(vec![b'x'; MAX_EVENT_BYTES + 1].into_boxed_slice());
    let events = tokenize_all(vec![b"data: ", huge]).await;

    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0],
        Err(ProviderError::MalformedEvent { .. })
    ));
}

#[tokio::test]
async fn nothing_is_emitted_after_a_terminal_error() {
    let events = tokenize_all(vec![b"data: \xff\xfe\n\ndata: {}\n\n"]).await;

    assert_eq!(
        events.len(),
        1,
        "a frame surfaced after the error that ended the stream"
    );
    assert!(matches!(
        events[0],
        Err(ProviderError::MalformedEvent { .. })
    ));
}

#[tokio::test]
async fn clean_eof_with_no_pending_lines_yields_nothing() {
    let events = tokenize_all(vec![b"event: a\ndata: {}\n\n", b"\n\n"]).await;

    assert_eq!(events.len(), 1, "trailing blank lines produced an event");
}

#[tokio::test]
async fn an_empty_stream_yields_nothing() {
    assert!(tokenize_all(vec![]).await.is_empty());
}
