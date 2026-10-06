//! The agent loop: drives a provider's streamed turn, dispatches the tool calls a
//! caller's gate lets through to `sandbx-tools`, and hands back replayable turns.
//!
//! [`run_turn`] is generic over a closure that opens a stream, so the whole loop runs
//! against canned events with no network and no API key. See
//! `context/guide-turn-loop.md`.

mod approval;
mod compact;
mod error;
mod turn;

pub use approval::{ApprovalDecision, ToolCall};
pub use compact::Compaction;
pub use error::TurnError;
pub use turn::{PromptUsage, Turn, TurnLimits, TurnOutcome, run_turn};
