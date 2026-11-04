use std::io;

use bytes::Bytes;
use futures_util::{StreamExt, stream};
use sandbx_provider::ProviderError;

use super::{MAX_EVENT_BYTES, tokenize};

async fn tokenize_all(chunks: Vec<&'static [u8]>) -> Vec<Result<String, ProviderError>> {
    let byte_stream = stream::iter(
        chunks
            .into_iter()
            .map(|c| Ok::<_, io::Error>(Bytes::from_static(c))),
    );
    tokenize(byte_stream).collect().await
}

/// What tells a reset from a timeout is the source, so the boxing must keep it whole.
#[tokio::test]
async fn a_read_error_is_transport_with_it_as_the_source() {
    let byte_stream = stream::iter(vec![
        Ok(Bytes::from_static(b"data: before\n\n")),
        Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "reset by peer",
        )),
        Ok(Bytes::from_static(b"data: after\n\n")),
    ]);
    let events: Vec<_> = tokenize(byte_stream).collect().await;

    assert_eq!(
        events.len(),
        2,
        "not the frame, then the error, then nothing: {events:?}"
    );
    assert_eq!(events[0].as_ref().unwrap(), "before");
    let Err(ProviderError::Transport { source, .. }) = &events[1] else {
        panic!("{:?} is not a transport error", events[1]);
    };
    let source = source
        .downcast_ref::<io::Error>()
        .expect("the source is the stream's own error");
    assert_eq!(source.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(source.to_string(), "reset by peer");
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
