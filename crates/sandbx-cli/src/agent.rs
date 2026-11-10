//! `agent-run`: one prompt, one streamed answer, tool calls through the boundary.
//!
//! [`agent_run`] is the argv surface and the sequence that consumes it; [`tui`] is the same
//! turn drawn on a screen. [`gate`] decides which calls may run, [`prompt`] asks the
//! operator about one, [`render`] reports what happened, [`orientation`] and [`wrapup`]
//! bracket the turn.

#[path = "agent_run.rs"]
mod agent_run;
#[path = "agent_gate.rs"]
mod gate;
#[path = "agent_orientation.rs"]
mod orientation;
#[path = "agent_prompt.rs"]
mod prompt;
#[path = "agent_render.rs"]
mod render;
#[path = "tui.rs"]
mod tui;
#[path = "agent_wrapup.rs"]
mod wrapup;

pub use agent_run::AgentRun;
pub use tui::Tui;

pub(crate) use prompt::APPROVE_CALL;

// Reached as `super::…` from the sibling modules rather than used here: `tui` takes the
// prompt types, the exit codes and `stored_stop`, `render` the exit codes.
use agent_run::{INCOMPLETE, NO_CONSENT, stored_stop};
use prompt::{Approve, Terminal};

/// Whether a stream reaches a terminal: what decides both that an SGR escape renders on it
/// and that a screen can be drawn on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Device {
    Terminal,
    Redirected,
}

impl Device {
    fn of(stream: &impl std::io::IsTerminal) -> Self {
        if stream.is_terminal() {
            Self::Terminal
        } else {
            Self::Redirected
        }
    }
}
