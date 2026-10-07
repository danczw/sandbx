//! The shapes an Anthropic `data:` payload can take, and nothing that interprets
//! them.
//!
//! Every type is a record of a frame as the API sends it, with a catch-all variant
//! beside the tags it tolerates. Folding them is [`super::accumulate`]'s job.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(super) enum RawStreamEvent {
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
        // Absent in some documented frames, and not worth ending a turn over.
        #[serde(default)]
        usage: RawUsage,
    },
    MessageStop,
    Ping,
    Error {
        error: RawApiErrorBody,
    },
    /// Any `type` this file does not model — `server_tool_use` results, MCP events.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawMessageStart {
    #[serde(default)]
    pub(super) usage: RawUsage,
}

/// Token counts, as reported by `message_start` or `message_delta`.
///
/// One type for both: the shape is the same, and the `message_delta` counts are
/// cumulative, restating `input_tokens` and the cache counters because server-side
/// tool use inflates the input mid-stream. Taking input from `message_start` and only
/// output from the delta undercounts.
///
/// Every field is `Option` so a frame omitting one cannot end the turn, and so "not
/// reported" stays distinguishable from a reported zero.
#[derive(Debug, Deserialize, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct RawUsage {
    pub(super) input_tokens: Option<u32>,
    pub(super) output_tokens: Option<u32>,
    pub(super) cache_creation_input_tokens: Option<u32>,
    pub(super) cache_read_input_tokens: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(super) enum RawContentBlockStart {
    Text {
        #[allow(dead_code)] // API always sends "", nothing to read
        text: String,
    },
    Thinking {
        /// Always `""` in practice; the text arrives as deltas.
        thinking: String,
    },
    /// Reasoning the API withheld. Complete at `content_block_start`: it has no
    /// deltas and no signature, the `data` blob standing in for both.
    RedactedThinking {
        data: String,
    },
    // `input` on a tool_use start is always `{}` and so not modeled — the real
    // value only exists after accumulation.
    ToolUse {
        id: String,
        name: String,
    },
    /// A block type this file does not model — `server_tool_use`,
    /// `web_search_tool_result`. Parsed rather than rejected, so nothing accumulates
    /// and its deltas and `content_block_stop` are ignored in turn.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(super) enum RawDelta {
    TextDelta {
        text: String,
    },
    ThinkingDelta {
        thinking: String,
    },
    /// Exactly one per thinking block, immediately before its
    /// `content_block_stop`.
    SignatureDelta {
        signature: String,
    },
    InputJsonDelta {
        partial_json: String,
    },
    /// A delta type this file does not model — `citations_delta`.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawMessageDelta {
    /// Nullable on the wire, and null does happen — hence
    /// [`StopReason::Unspecified`](crate::event::StopReason::Unspecified).
    pub(super) stop_reason: Option<String>,
}

/// The vendor's error body: `{"type": ..., "message": ...}`.
///
/// An HTTP error response and an in-band SSE `error` event carry the same shape, so
/// one type serves `anthropic.rs`'s non-2xx mapping too.
#[derive(Debug, Deserialize)]
pub(crate) struct RawApiErrorBody {
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) message: String,
}

/// The envelope an HTTP error response wraps [`RawApiErrorBody`] in:
/// `{"type":"error","error":{...}}`, which [`RawStreamEvent::Error`] destructures
/// itself for the SSE `error` event.
#[derive(Debug, Deserialize)]
pub(crate) struct RawApiErrorEnvelope {
    pub(crate) error: RawApiErrorBody,
}
