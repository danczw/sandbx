//! Minimal Server-Sent Events framing over a byte stream.
//!
//! Knows the SSE framing rules and nothing about what any particular API puts in
//! `data:`. A frame is its `data` alone, `event:` dropped, so a second provider can
//! reuse it only if its payloads name their own type.

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use sandbx_provider::ProviderError;

/// Turn a byte stream into a stream of framed SSE events.
///
/// `bytes_stream()` chunks with no relation to line boundaries, and `data:` payloads
/// can be multi-byte UTF-8, so bytes are buffered raw and decoded only once a range
/// ends at a `\n`: splitting on `0x0A` is safe mid sequence, because no UTF-8
/// continuation or lead byte takes that value.
///
/// `Send` is stated rather than left to leak out of the opaque type, so a non-`Send`
/// field added to the state below fails here, not at the coercion in a client's `stream_chat`.
pub fn tokenize(
    bytes: impl Stream<Item = reqwest::Result<Bytes>> + Unpin + Send,
) -> impl futures_util::stream::FusedStream<Item = Result<String, ProviderError>> + Send {
    // `.fuse()`: `unfold` panics if polled after it returns `None`, and callers
    // drive this stream however they like.
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
/// Without one, `buf` grows unbounded when the stream never produces the `\n` the
/// framing waits for — a gateway answering with a large non-SSE body — and the
/// process is OOM-killed with no diagnostic. 4 MiB is orders of magnitude above any
/// real Anthropic frame.
const MAX_EVENT_BYTES: usize = 4 * 1024 * 1024;

struct TokenizerState<S> {
    bytes: S,
    buf: Vec<u8>,
    /// How far into `buf` the search for the next `\n` has looked; without it every
    /// arriving chunk rescans from 0, quadratic in the length of a line.
    scanned: usize,
    done: bool,
}

async fn next_event<S>(
    mut state: TokenizerState<S>,
) -> Option<(Result<String, ProviderError>, TokenizerState<S>)>
where
    S: Stream<Item = reqwest::Result<Bytes>> + Unpin,
{
    // Checked before anything is drained: `done` is set only just before a terminal
    // item, so draining what is buffered behind one would emit frames after the error
    // or EOF that ended the stream.
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
                    let detail = format!("non-UTF-8 SSE line: {source}");
                    return Some((Err(ProviderError::MalformedEvent { detail }), ended(state)));
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
        state.scanned = state.buf.len();
        if event_bytes + state.buf.len() > MAX_EVENT_BYTES {
            return Some((oversized(), ended(state)));
        }

        // The scan above has decoded the tail of a stream that ended on an earlier
        // turn. Return rather than poll again: `state.bytes` already yielded `None`.
        if state.done {
            if lines.is_empty() {
                return None; // clean EOF between events
            }
            // Trailing event with no final blank line before EOF.
            return Some((Ok(parse_event(&lines)), state));
        }

        match state.bytes.next().await {
            Some(Ok(chunk)) => state.buf.extend_from_slice(&chunk),
            Some(Err(source)) => {
                return Some((
                    Err(ProviderError::Transport {
                        detail: "reading response stream".to_string(),
                        source: Box::new(source),
                    }),
                    ended(state),
                ));
            }
            None => {
                state.done = true;
                // Whatever sits after the last `\n` is a line the sender never
                // terminated, and the scan above only yields lines ending at one — so
                // without this it is dropped, commonly the `message_stop` frame.
                // Terminated here, not decoded separately, so one scan owns the UTF-8
                // decode, CR trim and cap check.
                if !state.buf.is_empty() {
                    state.buf.push(b'\n');
                }
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

fn oversized() -> Result<String, ProviderError> {
    Err(ProviderError::MalformedEvent {
        detail: format!("a single SSE event exceeded {MAX_EVENT_BYTES} bytes"),
    })
}

fn parse_event(lines: &[String]) -> String {
    let mut data_lines = Vec::new();
    for line in lines {
        if let Some(rest) = line.strip_prefix("data:") {
            data_lines.push(rest.trim_start());
        }
        // `event:` restates the payload's type tag; `id:`/`retry:`/comments serve only a
        // Last-Event-ID resume, never done here. A frame of only those yields an empty `data`.
    }
    data_lines.join("\n")
}

#[cfg(test)]
#[path = "sse_tests.rs"]
mod tests;
