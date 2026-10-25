//! `agent-run`: one prompt, one streamed answer, tool calls through the boundary.
//!
//! [`run`] is the argv surface and the sequence that consumes it; [`tui`] is the same
//! turn drawn on a screen. [`gate`] decides which calls may run, [`prompt`] asks the
//! operator about one, [`render`] reports what happened, [`orientation`] and [`wrapup`]
//! bracket the turn.

mod gate;
mod orientation;
mod prompt;
mod render;
mod run;
mod tui;
mod wrapup;

pub use run::AgentRun;
pub use tui::Tui;

pub(crate) use prompt::APPROVE_CALL;

// Reached as `super::…` from the sibling modules rather than used here: `tui` takes the
// two prompt types and the two exit codes, `render` the exit codes, `wrapup` the renderer.
use prompt::{Approve, Terminal};
use render::Render;
use run::{INCOMPLETE, NO_CONSENT};
