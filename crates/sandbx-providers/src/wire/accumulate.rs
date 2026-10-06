//! Folding a sequence of [`super::payload`] frames into [`AgentEvent`]s.
//!
//! Two invariants live here: an unmodeled tag is skipped rather than ending the
//! stream, and a turn ends exactly once — an [`AgentEvent::Stop`] at `message_stop`,
//! or an `Err` if it never arrives.

use std::collections::{BTreeMap, VecDeque};

use futures_util::Stream;

use crate::error::ProviderError;
use crate::event::{AgentEvent, StopReason};
use crate::sse::RawSseEvent;

use super::payload::{RawContentBlockStart, RawDelta, RawStreamEvent, RawUsage};

/// Per-index accumulation state for an in-flight `tool_use` block, the only block
/// type whose deltas mean nothing until they are buffered whole.
struct ToolUseBlock {
    id: String,
    name: String,
    partial_json: String,
}

/// Map a stream of raw SSE frames into [`AgentEvent`]s.
///
/// `Send` is stated, and the result fused, for the reasons `sse::tokenize` gives.
pub(crate) fn event_stream(
    raw: impl Stream<Item = Result<RawSseEvent, ProviderError>> + Send,
) -> impl futures_util::stream::FusedStream<Item = Result<AgentEvent, ProviderError>> + Send {
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
    /// Keyed by block index. A `BTreeMap`, not a `HashMap`: blocks still open when the
    /// turn ends flush in index order, which a randomized iteration order would make
    /// unreproducible.
    blocks: BTreeMap<u32, ToolUseBlock>,
    /// The turn's counts so far, each field the most recent value reported for it.
    usage: RawUsage,
    /// Held until `message_stop` — `message_delta` reporting a reason is not itself
    /// the end of the stream.
    stop_reason: Option<StopReason>,
    pending: VecDeque<Result<AgentEvent, ProviderError>>,
    ended: bool,
}

impl RawUsage {
    /// Overlay a newer report: each field it carries wins, each field it omits keeps
    /// the value held, since `message_delta` restates the counts cumulatively.
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

    /// Whether any count was reported; a turn with none emits no
    /// [`AgentEvent::Usage`] rather than one full of zeros.
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
    /// From `message_stop` only, covering a turn that ends properly with a `tool_use`
    /// block whose `content_block_stop` went missing: dropping the call would leave
    /// `Stop { reason: ToolUse }` telling the caller to run a tool it never got. The
    /// paths that end without `message_stop` do not flush — a truncated block's JSON
    /// is incomplete, so flushing would put a `MalformedEvent` ahead of the honest
    /// [`ProviderError::StreamEndedUnexpectedly`].
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
    // A tool call taking no arguments sends no `input_json_delta`, or one carrying
    // `""`, so an empty buffer means `{}` and not a parse failure. Reporting it as
    // malformed would leave a `Stop { ToolUse }` the caller cannot answer, and the API
    // rejects the next request for an unanswered `tool_use`.
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

        // A CDN or proxy heartbeat, which `sse.rs` reports as a frame with an empty
        // payload. Treating `""` as malformed would end a healthy turn the moment an
        // intermediary inserted one.
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
                // A non-tool start still clears the index: a stream that reuses one
                // without closing it — `tool_use` at 0, then `text` at 0 — would
                // otherwise accumulate the text deltas into the abandoned tool call
                // and emit a `ToolCallRequested` the model never asked for.
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
                // Recorded, not emitted: the counts are cumulative and several of
                // these arrive, so one `Usage` is queued at the end of the turn.
                state.usage.absorb(usage);
                if let Some(reason) = delta.stop_reason {
                    state.stop_reason = Some(StopReason::from_wire(&reason));
                }
            }
            RawStreamEvent::MessageStop => {
                state.ended = true;
                state.flush_open_blocks();
                state.push_usage();
                // Always a `Stop`, even when no frame named a reason: the alternative
                // is a stream that runs out, indistinguishable from a truncation.
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
