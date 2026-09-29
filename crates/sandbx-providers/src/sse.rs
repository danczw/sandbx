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
/// relation to line boundaries, and `data:` payloads can contain multi-byte
/// UTF-8. Splitting on the *byte* `0x0A` is safe even mid multi-byte sequence,
/// because UTF-8 continuation/lead bytes never take that value — only a literal
/// `\n` does. So bytes are buffered raw and only turned into a `String` once a
/// range ends exactly at a `\n`.
pub(crate) fn tokenize(
    bytes: impl Stream<Item = reqwest::Result<Bytes>> + Unpin,
) -> impl futures_util::stream::FusedStream<Item = Result<RawSseEvent, ProviderError>> {
    // `.fuse()`: `unfold` panics outright if polled after it returns `None`
    // (futures-util's `Unfold::poll_next` says so), and callers drive this stream
    // however they like — a `select!` arm that does not break on `None`, one
    // `.next()` too many after a `while let`. `FusedStream` makes over-polling
    // safe *and* visible in the signature.
    futures_util::StreamExt::fuse(futures_util::stream::unfold(
        TokenizerState {
            bytes,
            buf: Vec::new(),
            scanned: 0,
            done: false,
        },
        next_event,
    ))
}

/// Cap on the bytes a single SSE event may occupy before it is rejected.
///
/// Without one, `buf` grows unbounded whenever the stream never produces the
/// byte the framing waits for — a gateway answering with a large non-SSE body
/// containing no `\n`, or `data:` lines that never reach the blank line ending
/// the event — and the process is OOM-killed with no diagnostic. 4 MiB is orders
/// of magnitude above any real Anthropic frame, so the only streams this can
/// reject are already broken ones.
const MAX_EVENT_BYTES: usize = 4 * 1024 * 1024;

struct TokenizerState<S> {
    bytes: S,
    buf: Vec<u8>,
    /// How far into `buf` the search for the next `\n` has already looked.
    ///
    /// Without it, every arriving chunk rescans the whole buffer from index 0,
    /// which is quadratic in the length of a long line — the newline is known
    /// not to be in the bytes already examined.
    scanned: usize,
    done: bool,
}

async fn next_event<S>(
    mut state: TokenizerState<S>,
) -> Option<(Result<RawSseEvent, ProviderError>, TokenizerState<S>)>
where
    S: Stream<Item = reqwest::Result<Bytes>> + Unpin,
{
    // Checked before anything is drained, not after: `done` is only ever set
    // immediately before returning a terminal item, so bytes still buffered
    // behind one belong to a stream that already ended. Draining them first
    // would emit frames *after* the error or EOF that ended it.
    if state.done {
        return None;
    }

    let mut lines: Vec<String> = Vec::new();
    let mut event_bytes = 0usize;
    loop {
        while let Some(offset) = state.buf[state.scanned..].iter().position(|&b| b == b'\n') {
            let pos = state.scanned + offset;
            state.scanned = 0;
            let mut line: Vec<u8> = state.buf.drain(..=pos).collect();
            line.pop(); // trailing '\n'
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            let line = match String::from_utf8(line) {
                Ok(line) => line,
                Err(source) => {
                    return Some((
                        Err(ProviderError::MalformedEvent {
                            detail: format!("non-UTF-8 SSE line: {source}"),
                        }),
                        ended(state),
                    ));
                }
            };
            if line.is_empty() {
                if lines.is_empty() {
                    continue; // blank keep-alive between events
                }
                return Some((Ok(parse_event(&lines)), state));
            }
            event_bytes += line.len();
            if event_bytes > MAX_EVENT_BYTES {
                return Some((oversized(), ended(state)));
            }
            lines.push(line);
        }
        // Everything buffered has been examined and holds no newline.
        state.scanned = state.buf.len();
        if event_bytes + state.buf.len() > MAX_EVENT_BYTES {
            return Some((oversized(), ended(state)));
        }

        match state.bytes.next().await {
            Some(Ok(chunk)) => state.buf.extend_from_slice(&chunk),
            Some(Err(source)) => {
                return Some((
                    Err(ProviderError::Transport {
                        detail: "reading response stream".to_string(),
                        source,
                    }),
                    ended(state),
                ));
            }
            None => {
                state.done = true;
                // Whatever sits after the last `\n` is a final line the sender
                // never terminated — the loop above can only produce a line
                // that ends at a newline, so without this it is silently
                // dropped. That payload is commonly the `message_stop` frame,
                // i.e. the difference between a clean turn and a truncated one.
                if !state.buf.is_empty() {
                    let rest = std::mem::take(&mut state.buf);
                    match String::from_utf8(rest) {
                        Ok(line) => {
                            let line = line.trim_end_matches('\r');
                            if !line.is_empty() {
                                lines.push(line.to_string());
                            }
                        }
                        Err(source) => {
                            return Some((
                                Err(ProviderError::MalformedEvent {
                                    detail: format!("non-UTF-8 SSE line: {source}"),
                                }),
                                state,
                            ));
                        }
                    }
                }
                if lines.is_empty() {
                    return None; // clean EOF between events
                }
                // Trailing event with no final blank line before EOF.
                return Some((Ok(parse_event(&lines)), state));
            }
        }
    }
}

/// Mark the stream finished and drop anything still buffered, so the terminal
/// item this accompanies is genuinely the last one.
fn ended<S>(mut state: TokenizerState<S>) -> TokenizerState<S> {
    state.done = true;
    state.buf = Vec::new();
    state.scanned = 0;
    state
}

fn oversized() -> Result<RawSseEvent, ProviderError> {
    Err(ProviderError::MalformedEvent {
        detail: format!("a single SSE event exceeded {MAX_EVENT_BYTES} bytes"),
    })
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
        // resumes a stream via Last-Event-ID. A frame built only from those
        // yields an empty `data`; `wire.rs` skips it rather than failing to
        // parse `""`.
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
    /// should be lost if the connection closes without one — including the
    /// unterminated *final line*, which is where the payload lives. Asserting
    /// only `.event` here would pass while `.data` was silently dropped.
    #[tokio::test]
    async fn a_trailing_event_with_no_final_blank_line_is_not_dropped() {
        let events = tokenize_all(vec![b"event: message_stop\ndata: {}"]).await;

        assert_eq!(events.len(), 1);
        let event = events[0].as_ref().unwrap();
        assert_eq!(event.event.as_deref(), Some("message_stop"));
        assert_eq!(event.data, "{}", "the unterminated final line was dropped");
    }

    /// The same, split so the last chunk ends mid-line and carries no newline
    /// at all — the shape a connection reset produces.
    #[tokio::test]
    async fn an_unterminated_final_line_split_across_chunks_survives() {
        let events = tokenize_all(vec![b"data: {\"ty", b"pe\":\"message_stop\"}"]).await;

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].as_ref().unwrap().data,
            "{\"type\":\"message_stop\"}"
        );
    }

    #[tokio::test]
    async fn id_and_comment_lines_are_ignored() {
        let events = tokenize_all(vec![b": keep-alive comment\nid: 5\ndata: {}\n\n"]).await;

        assert_eq!(events[0].as_ref().unwrap().data, "{}");
    }

    /// A frame made only of ignored lines — what a CDN or proxy heartbeat looks
    /// like — is still a frame, and comes out with an empty payload rather than
    /// being swallowed. `wire.rs` is what skips it; this pins the shape it has
    /// to skip.
    #[tokio::test]
    async fn a_comment_only_frame_yields_an_empty_payload() {
        let events = tokenize_all(vec![b": keep-alive\n\ndata: {}\n\n"]).await;

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].as_ref().unwrap().data, "");
        assert_eq!(events[1].as_ref().unwrap().data, "{}");
    }

    /// A body that never produces the newline the framing waits for must be
    /// rejected rather than buffered until the process dies.
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

    /// Once a terminal item is returned, whatever was already buffered behind
    /// it must not surface as further frames.
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

    /// The blank line that ends the last event leaves nothing buffered, so EOF
    /// arrives with no pending lines and must yield nothing at all — the path
    /// that would otherwise emit a phantom empty event after every stream.
    #[tokio::test]
    async fn clean_eof_with_no_pending_lines_yields_nothing() {
        let events = tokenize_all(vec![b"event: a\ndata: {}\n\n", b"\n\n"]).await;

        assert_eq!(events.len(), 1, "trailing blank lines produced an event");
    }

    #[tokio::test]
    async fn an_empty_stream_yields_nothing() {
        assert!(tokenize_all(vec![]).await.is_empty());
    }
}
