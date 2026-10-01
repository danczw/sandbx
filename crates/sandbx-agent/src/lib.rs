//! The agent loop: drives a provider's streamed turn, dispatches the tool calls it
//! asks for through `sandbx-tools`, and hands back the result as replayable
//! conversation turns.
//!
//! The crate exists because `AgentEvent::Text` carries an increment rather than the
//! accumulated total, and nothing in `sandbx-providers` concatenates it — so without
//! a single owner, the agent loop, the TUI and any eval harness each rebuild the
//! same reassembly. It also owns the boundary between a synchronous tool and an
//! async runtime, which neither neighbouring crate's interface mentions.
//!
//! UI- and provider-agnostic by construction: [`run_turn`] is generic over a
//! closure that opens an event stream, so the whole loop runs against a canned
//! stream with no network access and no API key.

mod error;
mod turn;

pub use error::TurnError;
pub use turn::{Turn, run_turn};
