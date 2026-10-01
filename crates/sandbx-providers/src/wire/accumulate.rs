//! Folding a sequence of [`super::payload`] frames into [`AgentEvent`]s.
//!
//! The two invariants the module doc states are kept here: an unmodeled tag is
//! skipped rather than ending the stream, and a turn ends exactly once — with a
//! [`AgentEvent::Stop`] at `message_stop`, or with an `Err` if it never arrives.

use std::collections::{BTreeMap, VecDeque};

use futures_util::Stream;

use crate::error::ProviderError;
use crate::event::{AgentEvent, StopReason};
use crate::sse::RawSseEvent;

use super::payload::{RawContentBlockStart, RawDelta, RawStreamEvent, RawUsage};

/// Per-index accumulation state for an in-flight `tool_use` block.
///
/// Only `tool_use` is tracked, because it is the only block type whose deltas
/// have to be accumulated to mean anything — text and thinking deltas are emitted
/// as they arrive, and an unmodeled block has nothing to accumulate. An enum
/// covering the other kinds held variants that were inserted and never read.
struct ToolUseBlock {
    id: String,
    name: String,
    partial_json: String,
}

/// Map a stream of raw SSE frames into [`AgentEvent`]s.
pub(crate) fn event_stream(
    raw: impl Stream<Item = Result<RawSseEvent, ProviderError>>,
) -> impl futures_util::stream::FusedStream<Item = Result<AgentEvent, ProviderError>> {
    // `.fuse()` for the same reason as `sse::tokenize` — `unfold` panics if
    // polled once past its end, and this stream is handed to callers who drive
    // it however they like.
    futures_util::StreamExt::fuse(futures_util::stream::unfold(
        WireState {
            raw: Box::pin(raw),
            blocks: BTreeMap::new(),
            usage: RawUsage::default(),
            stop_reason: None,
            pending: VecDeque::new(),
            ended: false,
        },
        next_agent_event,
    ))
}

struct WireState<S> {
    raw: std::pin::Pin<Box<S>>,
    /// Keyed by block index. A `BTreeMap`, not a `HashMap`: blocks still open
    /// when the turn ends are flushed in index order, and a randomized
    /// iteration order would make that sequence unreproducible.
    blocks: BTreeMap<u32, ToolUseBlock>,
    /// The turn's counts so far, each field holding the most recent value the
    /// API reported for it.
    usage: RawUsage,
    /// The stop reason, held until `message_stop` decides the turn is over —
    /// `message_delta` reporting one is not itself the end of the stream.
    stop_reason: Option<StopReason>,
    pending: VecDeque<Result<AgentEvent, ProviderError>>,
    ended: bool,
}

impl RawUsage {
    /// Overlay a newer report: each field it actually carries wins, each field
    /// it omits keeps the value already held.
    ///
    /// Here rather than next to the struct because this is the fold rule, not
    /// part of the shape: `message_delta` restates the counts cumulatively, so
    /// what the turn reports is the newest value seen per field and nothing
    /// about the payload says that.
    fn absorb(&mut self, newer: Self) {
        self.input_tokens = newer.input_tokens.or(self.input_tokens);
        self.output_tokens = newer.output_tokens.or(self.output_tokens);
        self.cache_creation_input_tokens = newer
            .cache_creation_input_tokens
            .or(self.cache_creation_input_tokens);
        self.cache_read_input_tokens = newer
            .cache_read_input_tokens
            .or(self.cache_read_input_tokens);
    }

    /// Whether the API reported any count at all. A turn that reported none
    /// emits no [`AgentEvent::Usage`] rather than one full of zeros.
    fn reported(&self) -> bool {
        *self != Self::default()
    }
}

impl<S> WireState<S> {
    /// Queue the turn's token accounting, if there was any to report.
    fn push_usage(&mut self) {
        if !self.usage.reported() {
            return;
        }
        let RawUsage {
            input_tokens,
            output_tokens,
            cache_creation_input_tokens,
            cache_read_input_tokens,
        } = std::mem::take(&mut self.usage);
        self.pending.push_back(Ok(AgentEvent::Usage {
            input_tokens,
            output_tokens,
            cache_creation_input_tokens,
            cache_read_input_tokens,
        }));
    }

    /// Queue every tool call still open when the turn ended.
    ///
    /// Called from `message_stop` only, and deliberately: what it protects
    /// against is a turn that ends *properly* with a `tool_use` block whose
    /// `content_block_stop` went missing — a frame lost to a proxy. Without it
    /// the call is dropped on the floor while `Stop { reason: ToolUse }` still
    /// tells the caller to run a tool it was never given.
    ///
    /// The paths that end a turn without `message_stop` do not flush. They emit
    /// an `Err` instead of a `Stop`, so there is no instruction for a missing
    /// tool call to contradict, and the accumulated JSON of a genuinely truncated
    /// block is incomplete — flushing it would turn one honest
    /// [`ProviderError::StreamEndedUnexpectedly`] into a `MalformedEvent` ahead
    /// of it.
    fn flush_open_blocks(&mut self) {
        for (index, block) in std::mem::take(&mut self.blocks) {
            self.pending.push_back(tool_call_event(
                index,
                block.id,
                block.name,
                &block.partial_json,
            ));
        }
    }
}

fn tool_call_event(
    index: u32,
    id: String,
    name: String,
    partial_json: &str,
) -> Result<AgentEvent, ProviderError> {
    // A tool call taking no arguments sends no `input_json_delta` at all (or one
    // carrying `""`), so the buffer is still empty here and `{}` is the correct
    // input, not a parse failure. Reporting it as malformed would leave the
    // caller with a `Stop { ToolUse }` it cannot answer — no id, no name — and
    // the next request rejected for an unanswered `tool_use`. Both official SDKs
    // guard exactly this case.
    let input = if partial_json.trim().is_empty() {
        serde_json::Value::Object(serde_json::Map::new())
    } else {
        match serde_json::from_str(partial_json) {
            Ok(input) => input,
            Err(source) => {
                return Err(ProviderError::MalformedEvent {
                    detail: format!("tool_use input for block {index}: {source}"),
                });
            }
        }
    };
    Ok(AgentEvent::ToolCallRequested { id, name, input })
}

async fn next_agent_event<S>(
    mut state: WireState<S>,
) -> Option<(Result<AgentEvent, ProviderError>, WireState<S>)>
where
    S: Stream<Item = Result<RawSseEvent, ProviderError>>,
{
    use futures_util::StreamExt;

    loop {
        if let Some(event) = state.pending.pop_front() {
            return Some((event, state));
        }
        if state.ended {
            return None;
        }

        let raw = match state.raw.next().await {
            Some(Ok(raw)) => raw,
            Some(Err(error)) => {
                state.ended = true;
                state.push_usage();
                state.pending.push_back(Err(error));
                continue;
            }
            None => {
                state.ended = true;
                state.push_usage();
                state
                    .pending
                    .push_back(Err(ProviderError::StreamEndedUnexpectedly));
                continue;
            }
        };

        // A frame carrying no `data:` line at all — a CDN or proxy heartbeat
        // built from a comment line, which `sse.rs` correctly reports as a frame
        // with an empty payload. There is nothing to parse and nothing wrong:
        // treating `""` as a malformed event would end a perfectly healthy turn
        // the moment any intermediary inserted one.
        if raw.data.trim().is_empty() {
            continue;
        }

        let parsed: RawStreamEvent = match serde_json::from_str(&raw.data) {
            Ok(parsed) => parsed,
            Err(source) => {
                state.ended = true;
                state.pending.push_back(Err(ProviderError::MalformedEvent {
                    detail: format!("unrecognized stream event: {source}"),
                }));
                continue;
            }
        };

        match parsed {
            RawStreamEvent::MessageStart { message } => {
                state.usage.absorb(message.usage);
            }
            RawStreamEvent::ContentBlockStart {
                index,
                content_block,
            } => {
                // Only `tool_use` opens accumulation state; the other kinds are
                // parsed so they do not fail the turn, and then have nothing to
                // keep.
                //
                // A non-tool start still *clears* the index. Leaving a previous
                // entry there would let a stream that reuses an index without
                // closing it — `tool_use` at 0, then `text` at 0 — accumulate the
                // text block's deltas into the abandoned tool call and emit a
                // `ToolCallRequested` the model never asked for, which the agent
                // loop would then run. Opening a block ends whatever was open at
                // that index, whichever kind either one is.
                match content_block {
                    RawContentBlockStart::ToolUse { id, name } => {
                        state.blocks.insert(
                            index,
                            ToolUseBlock {
                                id,
                                name,
                                partial_json: String::new(),
                            },
                        );
                    }
                    _ => {
                        state.blocks.remove(&index);
                    }
                }
            }
            RawStreamEvent::ContentBlockDelta { index, delta } => match delta {
                RawDelta::TextDelta { text } => {
                    state
                        .pending
                        .push_back(Ok(AgentEvent::Text { delta: text }));
                }
                RawDelta::ThinkingDelta { thinking } => {
                    state
                        .pending
                        .push_back(Ok(AgentEvent::Thinking { delta: thinking }));
                }
                RawDelta::SignatureDelta { .. } => {
                    // Discarded — see AgentEvent::Thinking's doc.
                }
                RawDelta::InputJsonDelta { partial_json } => {
                    if let Some(block) = state.blocks.get_mut(&index) {
                        block.partial_json.push_str(&partial_json);
                    }
                }
                RawDelta::Unknown => {}
            },
            RawStreamEvent::ContentBlockStop { index } => {
                if let Some(block) = state.blocks.remove(&index) {
                    state.pending.push_back(tool_call_event(
                        index,
                        block.id,
                        block.name,
                        &block.partial_json,
                    ));
                }
            }
            RawStreamEvent::MessageDelta { delta, usage } => {
                // Recorded, not emitted: the counts are cumulative and there may
                // be several of these, so one `Usage` event is queued at the end
                // of the turn instead of one per frame that a consumer summing
                // them would double-count.
                state.usage.absorb(usage);
                if let Some(reason) = delta.stop_reason {
                    state.stop_reason = Some(StopReason::from_wire(&reason));
                }
            }
            RawStreamEvent::MessageStop => {
                state.ended = true;
                state.flush_open_blocks();
                state.push_usage();
                // Always a `Stop`, even when no frame ever named a reason: the
                // alternative is a stream that just runs out, indistinguishable
                // from a truncated turn.
                state.pending.push_back(Ok(AgentEvent::Stop {
                    reason: state.stop_reason.take().unwrap_or(StopReason::Unspecified),
                }));
            }
            RawStreamEvent::Ping | RawStreamEvent::Unknown => {}
            RawStreamEvent::Error { error } => {
                state.ended = true;
                state.push_usage();
                state.pending.push_back(Err(ProviderError::ApiError {
                    status: None,
                    kind: error.kind,
                    message: error.message,
                    retry_after: None,
                }));
            }
        }
    }
}
