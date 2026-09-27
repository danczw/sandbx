//! Anthropic-specific SSE payload shapes, and their accumulation into
//! [`AgentEvent`]s.
//!
//! Deserializes each `data:` payload by its own `"type"` tag — the `event:`
//! line is a redundant hint, never trusted alone, as defense against the two
//! ever disagreeing.
//!
//! `allow(dead_code)`: only exercised by this module's own tests until
//! `AnthropicClient` lands and becomes the real caller — remove once it does.
#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};

use futures_util::Stream;
use serde::Deserialize;

use crate::error::ProviderError;
use crate::event::{AgentEvent, StopReason};
use crate::sse::RawSseEvent;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum RawStreamEvent {
    MessageStart {
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
        delta: RawMessageDelta,
        usage: RawDeltaUsage,
    },
    MessageStop,
    Ping,
    Error {
        error: RawApiErrorBody,
    },
}

#[derive(Debug, Deserialize)]
struct RawMessageStart {
    usage: RawStartUsage,
}

#[derive(Debug, Deserialize, Default)]
struct RawStartUsage {
    input_tokens: u32,
    #[serde(default)]
    cache_creation_input_tokens: Option<u32>,
    #[serde(default)]
    cache_read_input_tokens: Option<u32>,
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
}

// Every variant ends in "Delta" on purpose: each name mirrors the wire's own
// `*_delta` tag value exactly, which is the point — a reader matching this
// against the API docs should not have to translate names.
#[allow(clippy::enum_variant_names)]
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
        #[allow(dead_code)] // accumulated for correctness; see AgentEvent::Thinking's doc
        signature: String,
    },
    InputJsonDelta {
        partial_json: String,
    },
}

#[derive(Debug, Deserialize)]
struct RawMessageDelta {
    stop_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawDeltaUsage {
    output_tokens: u32,
}

#[derive(Debug, Deserialize)]
struct RawApiErrorBody {
    #[serde(rename = "type")]
    kind: String,
    message: String,
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
}

/// Map a stream of raw SSE frames into [`AgentEvent`]s.
pub(crate) fn event_stream(
    raw: impl Stream<Item = Result<RawSseEvent, ProviderError>>,
) -> impl Stream<Item = Result<AgentEvent, ProviderError>> {
    futures_util::stream::unfold(
        WireState {
            raw: Box::pin(raw),
            blocks: HashMap::new(),
            start_usage: RawStartUsage::default(),
            pending: VecDeque::new(),
            ended: false,
        },
        next_agent_event,
    )
}

struct WireState<S> {
    raw: std::pin::Pin<Box<S>>,
    blocks: HashMap<u32, PartialBlock>,
    start_usage: RawStartUsage,
    pending: VecDeque<Result<AgentEvent, ProviderError>>,
    ended: bool,
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
                return Some((Err(error), state));
            }
            None => {
                state.ended = true;
                return Some((Err(ProviderError::StreamEndedUnexpectedly), state));
            }
        };

        let parsed: RawStreamEvent = match serde_json::from_str(&raw.data) {
            Ok(parsed) => parsed,
            Err(source) => {
                state.ended = true;
                return Some((
                    Err(ProviderError::MalformedEvent {
                        detail: format!("unrecognized stream event: {source}"),
                    }),
                    state,
                ));
            }
        };

        match parsed {
            RawStreamEvent::MessageStart { message } => {
                state.start_usage = message.usage;
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
                    // Nowhere to surface this yet — see AgentEvent::Thinking's doc.
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
            },
            RawStreamEvent::ContentBlockStop { index } => {
                if let Some(PartialBlock::ToolUse {
                    id,
                    name,
                    partial_json,
                }) = state.blocks.remove(&index)
                {
                    match serde_json::from_str::<serde_json::Value>(&partial_json) {
                        Ok(input) => state.pending.push_back(Ok(AgentEvent::ToolCallRequested {
                            id,
                            name,
                            input,
                        })),
                        Err(source) => {
                            state.pending.push_back(Err(ProviderError::MalformedEvent {
                                detail: format!("tool_use input for block {index}: {source}"),
                            }));
                        }
                    }
                }
            }
            RawStreamEvent::MessageDelta { delta, usage } => {
                state.pending.push_back(Ok(AgentEvent::Usage {
                    input_tokens: state.start_usage.input_tokens,
                    output_tokens: usage.output_tokens,
                    cache_creation_input_tokens: state.start_usage.cache_creation_input_tokens,
                    cache_read_input_tokens: state.start_usage.cache_read_input_tokens,
                }));
                if let Some(reason) = delta.stop_reason {
                    state.pending.push_back(Ok(AgentEvent::Stop {
                        reason: StopReason::from_wire(&reason),
                    }));
                }
            }
            RawStreamEvent::MessageStop => {
                state.ended = true;
            }
            RawStreamEvent::Ping => {}
            RawStreamEvent::Error { error } => {
                state.ended = true;
                state.pending.push_back(Err(ProviderError::ApiError {
                    status: None,
                    kind: error.kind,
                    message: error.message,
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
                    input_tokens: 10,
                    output_tokens: 5,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None,
                },
                AgentEvent::Stop {
                    reason: StopReason::EndTurn
                },
            ]
        );
    }

    #[tokio::test]
    async fn ping_produces_no_event() {
        let out = events(vec![
            raw(r#"{"type":"ping"}"#),
            raw(r#"{"type":"message_stop"}"#),
        ])
        .await;
        assert!(out.is_empty());
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

        assert!(out.is_empty());
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
            vec![AgentEvent::ToolCallRequested {
                id: "toolu_01A".to_string(),
                name: "get_weather".to_string(),
                input: serde_json::json!({"location": "Paris"}),
            }],
            "expected exactly one event, only after every fragment arrived"
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
            ]
        );
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

        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], Err(ProviderError::MalformedEvent { .. })));
    }

    #[tokio::test]
    async fn an_unknown_event_type_is_malformed_not_a_panic() {
        let out = events(vec![raw(r#"{"type":"some_future_event"}"#)]).await;

        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], Err(ProviderError::MalformedEvent { .. })));
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
    async fn message_stop_ends_the_stream_cleanly() {
        let out = events(vec![raw(r#"{"type":"message_stop"}"#)]).await;

        assert!(out.is_empty(), "message_stop itself produces no event");
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
}
