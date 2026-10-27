//! The turn loop: drives a provider's streamed turn, dispatches the tool calls a
//! caller's gate lets through to `sandbx-tools`, and hands back replayable turns.
//!
//! [`run_turn`] is generic over a closure that opens a stream, so the whole loop runs against
//! canned events with no network and no API key. See `context/guide-turn-loop.md`.
//!
//! `run` holds the round loop and the public types it is driven by, `accumulate` rebuilds a
//! round's message from deltas, `tools` runs what it asked for. Spans and not links: a crate
//! `//!` may not link a private item.

mod accumulate;
mod error;
mod run;
mod tools;

pub use error::TurnError;
pub use run::{Turn, TurnLimits, TurnOutcome, TurnStop, run_turn};
pub use sandbx_compact::{Compaction, PromptUsage};
