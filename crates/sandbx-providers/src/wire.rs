//! Anthropic-specific SSE payload shapes, and their accumulation into
//! [`AgentEvent`]s.
//!
//! Each `data:` payload is deserialized by its own `"type"` tag, and the
//! `event:` line is ignored entirely: it only ever restates that tag, so
//! reading it would add a second source of truth without adding information.
//! (It is still parsed by `sse.rs`, which is provider-agnostic and cannot know
//! that, and it remains useful when reading a captured stream by hand.)
//!
//! Two invariants this file owes its caller, both of which used to be violated
//! by shapes the API really produces:
//!
//! - **Unknown is not fatal.** Anthropic's streaming docs say new event types
//!   ship over time and clients must tolerate them. Since a parse failure here
//!   ends the stream, every tagged enum below has a catch-all so one unmodeled
//!   tag cannot discard the rest of a turn the user already paid for.
//! - **Every turn ends once, explicitly.** A completed turn emits exactly one
//!   [`AgentEvent::Stop`], at `message_stop`; a turn that never gets there ends
//!   with an `Err`. There is no third outcome where the stream simply stops.

use std::collections::{BTreeMap, VecDeque};

use futures_util::Stream;
use serde::Deserialize;

use crate::error::ProviderError;
use crate::event::{AgentEvent, StopReason};
use crate::sse::RawSseEvent;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum RawStreamEvent {
    MessageStart {
        #[serde(default)]
        message: RawMessageStart,
    },
    ContentBlockStart {
        index: u32,
        content_block: RawContentBlockStart,
    },
    ContentBlockDelta {
        index: u32,
        delta: RawDelta,
    },
    ContentBlockStop {
        index: u32,
    },
    MessageDelta {
        #[serde(default)]
        delta: RawMessageDelta,
        // Absent in some documented frames, and a missing token count is not
        // worth ending a turn over — see `RawUsage`.
        #[serde(default)]
        usage: RawUsage,
    },
    MessageStop,
    Ping,
    Error {
        error: RawApiErrorBody,
    },
    /// Any `type` this file does not model: `server_tool_use` results, MCP
    /// events, whatever ships next. Ignored, not fatal — see the module doc.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize, Default)]
struct RawMessageStart {
    #[serde(default)]
    usage: RawUsage,
}

/// Token counts, as reported by `message_start` *or* `message_delta`.
///
/// One type for both because the wire shape is the same, and because treating
/// them as the same thing is the fix for a real undercount: the docs state the
/// `message_delta` counts are *cumulative*, and a delta restates
/// `input_tokens`/the cache counters — server-side tool use inflates the input
/// mid-stream, by a factor of four in Anthropic's own web-search example. Taking
/// input from `message_start` and only output from the delta silently reports
/// the pre-inflation figure.
///
/// Every field is optional so that a frame omitting one cannot end the turn, and
/// so "not reported" stays distinguishable from a reported zero. `Option`
/// fields need no `#[serde(default)]`: serde's `missing_field` already resolves
/// an absent one to `None`.
#[derive(Debug, Deserialize, Default, Clone, Copy, PartialEq, Eq)]
struct RawUsage {
    input_tokens: Option<u32>,
    output_tokens: Option<u32>,
    cache_creation_input_tokens: Option<u32>,
    cache_read_input_tokens: Option<u32>,
}

impl RawUsage {
    /// Overlay a newer report: each field it actually carries wins, each field
    /// it omits keeps the value already held.
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

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum RawContentBlockStart {
    Text {
        #[allow(dead_code)] // API always sends "", nothing to read
        text: String,
    },
    Thinking {
        #[allow(dead_code)]
        thinking: String,
    },
    // `input` on a tool_use start is always `{}` and deliberately not
    // modeled — the real value only exists after accumulation.
    ToolUse {
        id: String,
        name: String,
    },
    /// A block type this file does not model — `server_tool_use`,
    /// `web_search_tool_result`, a `fallback` marker. Tracked as an opaque open
    /// block so its deltas and its `content_block_stop` stay accounted for.
    #[serde(other)]
    Unknown,
}

// The `*Delta` variant names mirror the wire's own `*_delta` tag values exactly,
// so a reader matching this against the API docs does not have to translate
// names.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum RawDelta {
    TextDelta {
        text: String,
    },
    ThinkingDelta {
        thinking: String,
    },
    SignatureDelta {
        #[allow(dead_code)] // discarded; see AgentEvent::Thinking's doc
        signature: String,
    },
    InputJsonDelta {
        partial_json: String,
    },
    /// A delta type this file does not model — `citations_delta`, and whatever
    /// follows it. Ignored, not fatal.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize, Default)]
struct RawMessageDelta {
    /// Nullable on the wire, and null does happen — hence
    /// [`StopReason::Unspecified`] rather than emitting no `Stop` at all.
    stop_reason: Option<String>,
}

/// The vendor's error body: `{"type": ..., "message": ...}`.
///
/// Shared with `anthropic.rs`'s non-2xx mapping rather than declared twice: an
/// HTTP error response and an in-band SSE `error` event carry the same shape
/// and both land in [`ProviderError::ApiError`], so one type serves both.
#[derive(Debug, Deserialize)]
pub(crate) struct RawApiErrorBody {
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) message: String,
}

/// The envelope an HTTP error response wraps [`RawApiErrorBody`] in:
/// `{"type":"error","error":{...}}`. The SSE `error` event uses the same
/// envelope, destructured by [`RawStreamEvent::Error`] instead.
#[derive(Debug, Deserialize)]
pub(crate) struct RawApiErrorEnvelope {
    pub(crate) error: RawApiErrorBody,
}

/// Per-index accumulation state for an in-flight content block.
enum PartialBlock {
    Text,
    Thinking,
    ToolUse {
        id: String,
        name: String,
        partial_json: String,
    },
    /// An open block of a type this file does not model.
    Unknown,
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
    blocks: BTreeMap<u32, PartialBlock>,
    /// The turn's counts so far, each field holding the most recent value the
    /// API reported for it.
    usage: RawUsage,
    /// The stop reason, held until `message_stop` decides the turn is over —
    /// `message_delta` reporting one is not itself the end of the stream.
    stop_reason: Option<StopReason>,
    pending: VecDeque<Result<AgentEvent, ProviderError>>,
    ended: bool,
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
    /// Without this, a `tool_use` block whose `content_block_stop` never arrives
    /// — a truncated turn, or a frame lost to a proxy — is dropped on the floor
    /// while `Stop { reason: ToolUse }` still tells the caller to run a tool it
    /// was never given.
    fn flush_open_blocks(&mut self) {
        for (index, block) in std::mem::take(&mut self.blocks) {
            if let PartialBlock::ToolUse {
                id,
                name,
                partial_json,
            } = block
            {
                self.pending
                    .push_back(tool_call_event(index, id, name, &partial_json));
            }
        }
    }
}

/// Turn an accumulated `tool_use` block into its event.
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
                let block = match content_block {
                    RawContentBlockStart::Text { .. } => PartialBlock::Text,
                    RawContentBlockStart::Thinking { .. } => PartialBlock::Thinking,
                    RawContentBlockStart::ToolUse { id, name } => PartialBlock::ToolUse {
                        id,
                        name,
                        partial_json: String::new(),
                    },
                    RawContentBlockStart::Unknown => PartialBlock::Unknown,
                };
                state.blocks.insert(index, block);
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
                    if let Some(PartialBlock::ToolUse {
                        partial_json: buffer,
                        ..
                    }) = state.blocks.get_mut(&index)
                    {
                        buffer.push_str(&partial_json);
                    }
                }
                RawDelta::Unknown => {}
            },
            RawStreamEvent::ContentBlockStop { index } => {
                if let Some(PartialBlock::ToolUse {
                    id,
                    name,
                    partial_json,
                }) = state.blocks.remove(&index)
                {
                    state
                        .pending
                        .push_back(tool_call_event(index, id, name, &partial_json));
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

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{StreamExt, stream};

    fn raw(data: &str) -> Result<RawSseEvent, ProviderError> {
        Ok(RawSseEvent {
            event: None,
            data: data.to_string(),
        })
    }

    async fn events(
        frames: Vec<Result<RawSseEvent, ProviderError>>,
    ) -> Vec<Result<AgentEvent, ProviderError>> {
        event_stream(stream::iter(frames)).collect().await
    }

    /// For tests asserting an all-success sequence. `ProviderError` does not
    /// derive `PartialEq` (it wraps an opaque `reqwest::Error`, which does
    /// not implement it either), so comparing a whole `Vec<Result<..>>`
    /// directly is not possible — unwrap first instead of weakening the
    /// error type just to make a test convenient.
    async fn ok_events(frames: Vec<Result<RawSseEvent, ProviderError>>) -> Vec<AgentEvent> {
        events(frames)
            .await
            .into_iter()
            .map(|event| event.expect("expected every event to parse"))
            .collect()
    }

    /// The `Stop` every completed turn ends with, for tests whose subject is
    /// what comes before it.
    fn stop(reason: StopReason) -> AgentEvent {
        AgentEvent::Stop { reason }
    }

    #[tokio::test]
    async fn message_start_and_message_delta_combine_into_one_usage_event() {
        let out = ok_events(vec![
            raw(r#"{"type":"message_start","message":{"usage":{"input_tokens":10}}}"#),
            raw(r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}"#),
            raw(r#"{"type":"message_stop"}"#),
        ])
        .await;

        assert_eq!(
            out,
            vec![
                AgentEvent::Usage {
                    input_tokens: Some(10),
                    output_tokens: Some(5),
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None,
                },
                stop(StopReason::EndTurn),
            ]
        );
    }

    /// The docs call the `message_delta` counts cumulative, and server-side tool
    /// use inflates `input_tokens` mid-stream — Anthropic's own web-search
    /// example jumps from 2679 to 10682. The delta's figures must win, or the
    /// turn is billed at a fraction of what it cost.
    #[tokio::test]
    async fn a_message_delta_restating_input_tokens_wins_over_message_start() {
        let out = ok_events(vec![
            raw(r#"{"type":"message_start","message":{"usage":{"input_tokens":2679,"cache_read_input_tokens":0}}}"#),
            raw(r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"input_tokens":10682,"cache_creation_input_tokens":0,"cache_read_input_tokens":4,"output_tokens":510}}"#),
            raw(r#"{"type":"message_stop"}"#),
        ])
        .await;

        assert_eq!(
            out[0],
            AgentEvent::Usage {
                input_tokens: Some(10682),
                output_tokens: Some(510),
                cache_creation_input_tokens: Some(0),
                cache_read_input_tokens: Some(4),
            }
        );
    }

    /// "One or more" `message_delta` events are documented, and the counts in
    /// each restate the totals. Exactly one `Usage` event must come out, or a
    /// consumer adding them up reports several times the real spend.
    #[tokio::test]
    async fn several_message_deltas_produce_exactly_one_usage_event() {
        let out = ok_events(vec![
            raw(r#"{"type":"message_start","message":{"usage":{"input_tokens":10}}}"#),
            raw(r#"{"type":"message_delta","delta":{"stop_reason":null},"usage":{"output_tokens":5}}"#),
            raw(r#"{"type":"message_delta","delta":{"stop_reason":null},"usage":{"output_tokens":9}}"#),
            raw(r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":12}}"#),
            raw(r#"{"type":"message_stop"}"#),
        ])
        .await;

        assert_eq!(
            out,
            vec![
                AgentEvent::Usage {
                    input_tokens: Some(10),
                    output_tokens: Some(12),
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None,
                },
                stop(StopReason::EndTurn),
            ],
            "the last cumulative figure, reported once"
        );
    }

    /// A turn that never reported a count emits no `Usage` at all, rather than
    /// one claiming a genuine zero.
    #[tokio::test]
    async fn a_turn_with_no_usage_reported_emits_no_usage_event() {
        let out = ok_events(vec![
            raw(r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"}}"#),
            raw(r#"{"type":"message_stop"}"#),
        ])
        .await;

        assert_eq!(out, vec![stop(StopReason::EndTurn)]);
    }

    /// A `message_delta` with no `usage` key, and a `message_start` with no
    /// `usage` key — the latter is the shape the docs' extended-thinking example
    /// shows. Neither is worth ending a paid turn over.
    #[tokio::test]
    async fn frames_missing_their_usage_field_do_not_end_the_turn() {
        let out = ok_events(vec![
            raw(r#"{"type":"message_start","message":{}}"#),
            raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#),
            raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}"#),
            raw(r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"}}"#),
            raw(r#"{"type":"message_stop"}"#),
        ])
        .await;

        assert_eq!(
            out,
            vec![
                AgentEvent::Text {
                    delta: "hi".to_string()
                },
                stop(StopReason::EndTurn),
            ]
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

    /// A field-name bug here (the wire field is "thinking", matching
    /// text_delta's "text" — not "delta") would silently break every
    /// extended-thinking stream with a deserialization error. Caught during
    /// review before this test existed; kept here so it cannot regress.
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

    /// A signature_delta accompanies a thinking block but has nowhere to go
    /// in AgentEvent yet (see its doc comment) — it must be consumed and
    /// ignored, not cause a parse failure.
    #[tokio::test]
    async fn signature_delta_is_accepted_and_produces_no_event() {
        let out = ok_events(vec![
            raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}"#),
            raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"abc123"}}"#),
            raw(r#"{"type":"content_block_stop","index":0}"#),
            raw(r#"{"type":"message_stop"}"#),
        ])
        .await;

        assert_eq!(out, vec![stop(StopReason::Unspecified)]);
    }

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

    /// The star case: a tool call's JSON input arrives in fragments, and must
    /// collapse into exactly one event with the fully parsed input.
    #[tokio::test]
    async fn a_tool_call_split_across_fragments_becomes_one_event() {
        let out = ok_events(vec![
            raw(r#"{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_01A","name":"get_weather"}}"#),
            raw(r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"loc"}}"#),
            raw(r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"ation\":\"Pa"}}"#),
            raw(r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"ris\"}"}}"#),
            raw(r#"{"type":"content_block_stop","index":1}"#),
            raw(r#"{"type":"message_stop"}"#),
        ])
        .await;

        assert_eq!(
            out,
            vec![
                AgentEvent::ToolCallRequested {
                    id: "toolu_01A".to_string(),
                    name: "get_weather".to_string(),
                    input: serde_json::json!({"location": "Paris"}),
                },
                stop(StopReason::Unspecified),
            ],
            "expected exactly one tool event, only after every fragment arrived"
        );
    }

    /// A tool taking no arguments sends no `input_json_delta` at all, so the
    /// accumulated buffer is empty at `content_block_stop`. `{}` is the input.
    /// Reporting that as malformed would hand the caller a `Stop { ToolUse }`
    /// with no call to answer, and the API rejects the next request for an
    /// unanswered `tool_use`.
    #[tokio::test]
    async fn a_zero_argument_tool_call_yields_an_empty_input() {
        let out = ok_events(vec![
            raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_01A","name":"get_time"}}"#),
            raw(r#"{"type":"content_block_stop","index":0}"#),
            raw(r#"{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":3}}"#),
            raw(r#"{"type":"message_stop"}"#),
        ])
        .await;

        assert_eq!(
            out[0],
            AgentEvent::ToolCallRequested {
                id: "toolu_01A".to_string(),
                name: "get_time".to_string(),
                input: serde_json::json!({}),
            }
        );
        assert_eq!(out.last(), Some(&stop(StopReason::ToolUse)));
    }

    /// The same call, but with the empty-string delta the API sends instead on
    /// some turns.
    #[tokio::test]
    async fn an_empty_input_json_delta_is_also_an_empty_input() {
        let out = ok_events(vec![
            raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_01A","name":"get_time"}}"#),
            raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":""}}"#),
            raw(r#"{"type":"content_block_stop","index":0}"#),
            raw(r#"{"type":"message_stop"}"#),
        ])
        .await;

        assert_eq!(
            out[0],
            AgentEvent::ToolCallRequested {
                id: "toolu_01A".to_string(),
                name: "get_time".to_string(),
                input: serde_json::json!({}),
            }
        );
    }

    /// Parallel tool calls (different indices) must accumulate and close out
    /// independently, interleaved or not.
    #[tokio::test]
    async fn two_parallel_tool_calls_accumulate_independently_by_index() {
        let out = ok_events(vec![
            raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_A","name":"get_weather"}}"#),
            raw(r#"{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_B","name":"get_time"}}"#),
            raw(r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"tz\":\"UTC\"}"}}"#),
            raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"location\":\"NYC\"}"}}"#),
            raw(r#"{"type":"content_block_stop","index":1}"#),
            raw(r#"{"type":"content_block_stop","index":0}"#),
            raw(r#"{"type":"message_stop"}"#),
        ])
        .await;

        assert_eq!(
            out,
            vec![
                AgentEvent::ToolCallRequested {
                    id: "toolu_B".to_string(),
                    name: "get_time".to_string(),
                    input: serde_json::json!({"tz": "UTC"}),
                },
                AgentEvent::ToolCallRequested {
                    id: "toolu_A".to_string(),
                    name: "get_weather".to_string(),
                    input: serde_json::json!({"location": "NYC"}),
                },
                stop(StopReason::Unspecified),
            ]
        );
    }

    /// A `tool_use` block whose `content_block_stop` never arrives must still be
    /// delivered at `message_stop`. Dropping it while still reporting
    /// `Stop { ToolUse }` tells the caller to run a tool it was never given.
    #[tokio::test]
    async fn a_tool_use_block_left_open_is_flushed_at_message_stop() {
        let out = ok_events(vec![
            raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_A","name":"get_weather"}}"#),
            raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"location\":\"NYC\"}"}}"#),
            raw(r#"{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":8}}"#),
            raw(r#"{"type":"message_stop"}"#),
        ])
        .await;

        assert_eq!(
            out.first(),
            Some(&AgentEvent::ToolCallRequested {
                id: "toolu_A".to_string(),
                name: "get_weather".to_string(),
                input: serde_json::json!({"location": "NYC"}),
            })
        );
        assert_eq!(out.last(), Some(&stop(StopReason::ToolUse)));
    }

    #[tokio::test]
    async fn unparseable_accumulated_json_is_a_malformed_event_not_a_panic() {
        let out = events(vec![
            raw(r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_X","name":"broken"}}"#),
            raw(r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"not json"}}"#),
            raw(r#"{"type":"content_block_stop","index":0}"#),
            raw(r#"{"type":"message_stop"}"#),
        ])
        .await;

        assert!(matches!(out[0], Err(ProviderError::MalformedEvent { .. })));
        // Unlike a frame that fails to parse, one unusable tool call does not
        // end the turn — the `message_stop` behind it is still honoured.
        assert!(matches!(out[1], Ok(AgentEvent::Stop { .. })));
    }

    /// The streaming docs say new event types ship over time and clients must
    /// tolerate them. Since a parse failure ends the stream, an unmodeled type
    /// must be ignored instead — otherwise `server_tool_use`, MCP or citations
    /// would discard the remainder of a paid turn with no code change here.
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

    /// The same tolerance one level down: an unmodeled content-block type and an
    /// unmodeled delta type, which is how `server_tool_use` and
    /// `citations_delta` arrive.
    #[tokio::test]
    async fn an_unknown_content_block_and_delta_are_ignored_not_fatal() {
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

    /// A frame carrying no `data:` line — an intermediary's keep-alive comment —
    /// reaches this layer as an empty payload. Failing to parse `""` would end
    /// an otherwise healthy turn on the whim of a proxy.
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

    #[tokio::test]
    async fn message_stop_ends_the_stream_with_a_stop_event() {
        let out = ok_events(vec![raw(r#"{"type":"message_stop"}"#)]).await;

        assert_eq!(
            out,
            vec![stop(StopReason::Unspecified)],
            "message_stop must always produce exactly one Stop"
        );
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

    /// Token counts are reported even when the turn is lost — they were billed.
    #[tokio::test]
    async fn usage_survives_a_truncated_turn() {
        let out = events(vec![raw(
            r#"{"type":"message_delta","delta":{"stop_reason":null},"usage":{"output_tokens":8}}"#,
        )])
        .await;

        assert!(matches!(out[0], Ok(AgentEvent::Usage { .. })));
        assert!(matches!(
            out[1],
            Err(ProviderError::StreamEndedUnexpectedly)
        ));
    }

    /// `unfold` panics outright if polled after it returns `None`, and this
    /// stream is handed to callers who may poll it once more — a `select!` arm
    /// that does not break on `None`, a stray `.next()` after a `while let`.
    /// Being fused is part of the contract, not an implementation detail.
    #[tokio::test]
    async fn the_stream_is_fused_and_survives_being_over_polled() {
        // Boxed only to poll it by hand: the stream holds the async body of
        // `next_agent_event` and so is not `Unpin`, which `.collect()` (taking
        // `self`) hides from every other test here but `.next()` does not.
        let mut stream = Box::pin(event_stream(stream::iter(vec![raw(
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
}
