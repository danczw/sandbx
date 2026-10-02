//! Anthropic-specific SSE payload shapes, and their accumulation into
//! [`AgentEvent`](crate::event::AgentEvent)s.
//!
//! [`payload`] is the wire shapes, one type per documented frame; [`accumulate`]
//! is the state machine that folds a sequence of them into events.
//!
//! Each `data:` payload is deserialized by its own `"type"` tag, and the `event:`
//! line is ignored: it only restates that tag.
//!
//! Two invariants this module owes its caller:
//!
//! - An unmodeled tag is not fatal. New event types ship over time, and a parse
//!   failure here ends the stream, so every tagged enum in [`payload`] has a
//!   catch-all rather than discarding the rest of a paid turn.
//! - Every turn ends once, explicitly: one
//!   [`AgentEvent::Stop`](crate::event::AgentEvent::Stop) at `message_stop`, or an
//!   `Err` if it never arrives. There is no third outcome.

mod accumulate;
mod payload;
#[cfg(test)]
mod tests;

pub(crate) use accumulate::event_stream;
pub(crate) use payload::RawApiErrorEnvelope;
