//! Anthropic-specific SSE payload shapes, and their accumulation into
//! [`AgentEvent`](sandbx_event::AgentEvent)s.
//!
//! Each `data:` payload is deserialized by its own `"type"` tag; the `event:` line
//! only restates that tag, so it is ignored.

#[path = "anthropic_wire_accumulate.rs"]
mod accumulate;
#[path = "anthropic_wire_payload.rs"]
mod payload;

pub(crate) use accumulate::event_stream;
pub(crate) use payload::RawApiErrorEnvelope;

#[cfg(test)]
#[path = "anthropic_wire_tests.rs"]
mod tests;
