//! `agent-run`: one prompt, one streamed answer, tool calls through the boundary.
//!
//! [`run`] is the argv surface and the sequence that consumes it; [`tui`] is the same
//! turn drawn on a screen. [`gate`] decides which calls may run, [`prompt`] asks the
//! operator about one, [`render`] reports what happened, [`orientation`] and [`wrapup`]
//! bracket the turn.

#[path = "agent_gate.rs"]
mod gate;
#[path = "agent_orientation.rs"]
mod orientation;
#[path = "agent_prompt.rs"]
mod prompt;
#[path = "agent_render.rs"]
mod render;
#[path = "agent_run.rs"]
mod run;
#[path = "agent_tui.rs"]
mod tui;
#[path = "agent_wrapup.rs"]
mod wrapup;

pub use run::AgentRun;
pub use tui::Tui;

pub(crate) use prompt::APPROVE_CALL;

// Reached as `super::…` from the sibling modules rather than used here: `tui` takes the
// two prompt types and the two exit codes, `render` the exit codes, `wrapup` the renderer.
use prompt::{Approve, Terminal};
use render::Render;
use run::{INCOMPLETE, NO_CONSENT};
