//! The shapes an Anthropic `data:` payload can take, and nothing that interprets
//! them.
//!
//! Deserialization only: every type is a record of a frame as the API sends it,
//! catch-all variants beside the tags they tolerate. Folding a sequence of these
//! into [`AgentEvent`](crate::event::AgentEvent)s is [`super::accumulate`]'s job.

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
        // Absent in some documented frames; a missing count is not worth ending a
        // turn over — see `RawUsage`.
        #[serde(default)]
        usage: RawUsage,
    },
    MessageStop,
    Ping,
    Error {
        error: RawApiErrorBody,
    },
    /// Any `type` this file does not model — `server_tool_use` results, MCP events.
    /// Ignored, not fatal; see the module doc.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawMessageStart {
    #[serde(default)]
    pub(super) usage: RawUsage,
}

/// Token counts, as reported by `message_start` *or* `message_delta`.
///
/// One type for both: the shape is the same, and the `message_delta` counts are
/// *cumulative*, restating `input_tokens` and the cache counters because
/// server-side tool use inflates the input mid-stream. Taking input from
/// `message_start` and only output from the delta undercounts.
///
/// Every field is `Option` so a frame omitting one cannot end the turn, and so "not
/// reported" stays distinguishable from a reported zero. No `#[serde(default)]`
/// needed: serde resolves an absent `Option` field to `None`.
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
        #[allow(dead_code)]
        thinking: String,
    },
    // `input` on a tool_use start is always `{}` and so not modeled — the real
    // value only exists after accumulation.
    ToolUse {
        id: String,
        name: String,
    },
    /// A block type this file does not model — `server_tool_use`,
    /// `web_search_tool_result`. Parsed rather than rejected so it does not fail the
    /// turn; nothing accumulates, and its deltas and `content_block_stop` are
    /// ignored in turn.
    #[serde(other)]
    Unknown,
}

// The `*Delta` variant names mirror the wire's own `*_delta` tag values exactly.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(super) enum RawDelta {
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
    /// A delta type this file does not model — `citations_delta`. Ignored, not
    /// fatal.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct RawMessageDelta {
    /// Nullable on the wire, and null does happen — hence
    /// [`StopReason::Unspecified`](crate::event::StopReason::Unspecified) rather
    /// than emitting no `Stop` at all.
    pub(super) stop_reason: Option<String>,
}

/// The vendor's error body: `{"type": ..., "message": ...}`.
///
/// An HTTP error response and an in-band SSE `error` event carry the same shape and
/// both land in
/// [`ProviderError::ApiError`](crate::error::ProviderError::ApiError), so one type
/// serves `anthropic.rs`'s non-2xx mapping too.
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
