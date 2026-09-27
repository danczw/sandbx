//! Minimal Server-Sent Events framing over a byte stream.
//!
//! Knows the SSE framing rules and nothing about what any particular API puts
//! in `data:` — kept separate from `wire.rs` so a second SSE-based provider
//! (OpenAI's streaming format is also SSE) could reuse this file unchanged.

use bytes::Bytes;
use futures_util::{Stream, StreamExt};

use crate::ProviderError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawSseEvent {
    pub event: Option<String>,
    pub data: String,
}

/// Turn a byte stream into a stream of framed SSE events.
///
/// `reqwest`'s `bytes_stream()` yields arbitrarily-chunked bytes with no
/// relation to line boundaries — a `\n` can land split across two chunks, and
/// `data:` payloads can contain multi-byte UTF-8 (emoji, non-ASCII tool
/// arguments). Splitting on the *byte* `0x0A` is always safe even mid
/// multi-byte sequence, because UTF-8 continuation/lead bytes never take the
/// value `0x0A` — only a literal `\n` does. So bytes are buffered raw and only
/// turned into a `String` once a range ends exactly at a `\n`.
pub(crate) fn tokenize(
    bytes: impl Stream<Item = reqwest::Result<Bytes>> + Unpin,
) -> impl Stream<Item = Result<RawSseEvent, ProviderError>> {
    futures_util::stream::unfold(
        TokenizerState {
            bytes,
            buf: Vec::new(),
            done: false,
        },
        next_event,
    )
}

struct TokenizerState<S> {
    bytes: S,
    buf: Vec<u8>,
    done: bool,
}

async fn next_event<S>(
    mut state: TokenizerState<S>,
) -> Option<(Result<RawSseEvent, ProviderError>, TokenizerState<S>)>
where
    S: Stream<Item = reqwest::Result<Bytes>> + Unpin,
{
    let mut lines: Vec<String> = Vec::new();
    loop {
        while let Some(pos) = state.buf.iter().position(|&b| b == b'\n') {
            let mut line: Vec<u8> = state.buf.drain(..=pos).collect();
            line.pop(); // trailing '\n'
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            let line = match String::from_utf8(line) {
                Ok(line) => line,
                Err(source) => {
                    state.done = true;
                    return Some((
                        Err(ProviderError::MalformedEvent {
                            detail: format!("non-UTF-8 SSE line: {source}"),
                        }),
                        state,
                    ));
                }
            };
            if line.is_empty() {
                if lines.is_empty() {
                    continue; // blank keep-alive between events
                }
                return Some((Ok(parse_event(&lines)), state));
            }
            lines.push(line);
        }

        if state.done {
            return None;
        }

        match state.bytes.next().await {
            Some(Ok(chunk)) => state.buf.extend_from_slice(&chunk),
            Some(Err(source)) => {
                state.done = true;
                return Some((
                    Err(ProviderError::Transport {
                        detail: "reading response stream".to_string(),
                        source,
                    }),
                    state,
                ));
            }
            None => {
                state.done = true;
                if lines.is_empty() {
                    return None; // clean EOF between events
                }
                // Trailing event with no final blank line before EOF.
                return Some((Ok(parse_event(&lines)), state));
            }
        }
    }
}

fn parse_event(lines: &[String]) -> RawSseEvent {
    let mut event = None;
    let mut data_lines = Vec::new();
    for line in lines {
        if let Some(rest) = line.strip_prefix("event:") {
            event = Some(rest.trim_start().to_string());
        } else if let Some(rest) = line.strip_prefix("data:") {
            data_lines.push(rest.trim_start());
        }
        // id:/retry:/`:`-comment lines: accepted, ignored — this crate never
        // resumes a stream via Last-Event-ID.
    }
    RawSseEvent {
        event,
        data: data_lines.join("\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::stream;

    async fn tokenize_all(chunks: Vec<&'static [u8]>) -> Vec<Result<RawSseEvent, ProviderError>> {
        let byte_stream = stream::iter(chunks.into_iter().map(|c| Ok(Bytes::from_static(c))));
        tokenize(byte_stream).collect().await
    }

    #[tokio::test]
    async fn a_single_event_in_one_chunk() {
        let events = tokenize_all(vec![b"event: ping\ndata: {}\n\n"]).await;

        assert_eq!(events.len(), 1);
        let event = events[0].as_ref().unwrap();
        assert_eq!(event.event.as_deref(), Some("ping"));
        assert_eq!(event.data, "{}");
    }

    /// The whole reason for buffering raw bytes rather than lines: a chunk
    /// boundary can land anywhere, including mid-line.
    #[tokio::test]
    async fn an_event_split_across_chunks() {
        let events = tokenize_all(vec![b"event: ping\nda", b"ta: {}\n\n"]).await;

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].as_ref().unwrap().data, "{}");
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

        assert_eq!(events[0].as_ref().unwrap().data, "line one\nline two");
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

    /// A real stream ends with a blank line after the last event, but nothing
    /// should be lost if the connection closes without one.
    #[tokio::test]
    async fn a_trailing_event_with_no_final_blank_line_is_not_dropped() {
        let events = tokenize_all(vec![b"event: message_stop\ndata: {}"]).await;

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].as_ref().unwrap().event.as_deref(),
            Some("message_stop")
        );
    }

    #[tokio::test]
    async fn id_and_comment_lines_are_ignored() {
        let events = tokenize_all(vec![b": keep-alive comment\nid: 5\ndata: {}\n\n"]).await;

        assert_eq!(events[0].as_ref().unwrap().data, "{}");
    }

    #[tokio::test]
    async fn clean_eof_with_no_pending_lines_yields_nothing() {
        let events = tokenize_all(vec![b"event: a\ndata: {}\n\n"]).await;
        assert_eq!(events.len(), 1); // sanity: no phantom trailing event
    }
}
