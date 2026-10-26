//! Terminal UI: the screen a turn is drawn on, the keys that interrupt it, and the state
//! in between.
//!
//! Takes `&AgentEvent` and hands back a keypress. Model-chosen text is stripped in
//! [`sandbx_tui_transcript`], not at the caller, because the screen is what an escape
//! sequence inside it would rewrite.

mod input;
mod screen;

pub use input::{Keys, Stopped};
pub use sandbx_tui_transcript::Transcript;
pub use screen::Screen;
