//! Anthropic-specific SSE payload shapes, and their accumulation into
//! [`AgentEvent`](crate::event::AgentEvent)s.
//!
//! Split in two along that "and": [`payload`] is the wire shapes, one type per
//! documented frame and nothing that interprets them, and [`accumulate`] is the
//! state machine that folds a sequence of them into events.
//!
//! Each `data:` payload is deserialized by its own `"type"` tag, and the
//! `event:` line is ignored entirely: it only ever restates that tag, so
//! reading it would add a second source of truth without adding information.
//! (It is still parsed by `sse.rs`, which is provider-agnostic and cannot know
//! that, and it remains useful when reading a captured stream by hand.)
//!
//! Two invariants this module owes its caller, both of which used to be violated
//! by shapes the API really produces:
//!
//! - **Unknown is not fatal.** Anthropic's streaming docs say new event types
//!   ship over time and clients must tolerate them. Since a parse failure here
//!   ends the stream, every tagged enum in [`payload`] has a catch-all so one
//!   unmodeled tag cannot discard the rest of a turn the user already paid for.
//! - **Every turn ends once, explicitly.** A completed turn emits exactly one
//!   [`AgentEvent::Stop`](crate::event::AgentEvent::Stop), at `message_stop`; a
//!   turn that never gets there ends with an `Err`. There is no third outcome
//!   where the stream simply stops.

mod accumulate;
mod payload;
#[cfg(test)]
mod tests;

pub(crate) use accumulate::event_stream;
pub(crate) use payload::RawApiErrorEnvelope;
