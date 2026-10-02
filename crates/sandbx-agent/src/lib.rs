//! The agent loop: drives a provider's streamed turn, dispatches the tool calls it asks
//! for through `sandbx-tools`, and hands back replayable conversation turns.
//!
//! Owns what neither neighbour does: reassembling `AgentEvent::Text`, which carries an
//! increment rather than a running total, and the boundary between a synchronous tool
//! and an async runtime. [`run_turn`] is generic over a closure that opens a stream, so
//! the whole loop runs against canned events with no network access and no API key.

mod compact;
mod error;
mod turn;

pub use compact::Compaction;
pub use error::TurnError;
pub use turn::{PromptUsage, Turn, TurnLimits, TurnOutcome, run_turn};
