//! Anthropic-specific SSE payload shapes, and their accumulation into
//! [`AgentEvent`](crate::event::AgentEvent)s.
//!
//! Each `data:` payload is deserialized by its own `"type"` tag; the `event:` line
//! only restates that tag, so it is ignored.

mod accumulate;
mod payload;
#[cfg(test)]
mod tests;

pub(crate) use accumulate::event_stream;
pub(crate) use payload::RawApiErrorEnvelope;
