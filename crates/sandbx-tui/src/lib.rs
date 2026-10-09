//! Terminal UI: the screen a turn is drawn on, the keys that interrupt it, and the state
//! in between.
//!
//! Takes `&AgentEvent` and hands back a keypress; model-chosen text is stripped here, not
//! at the caller, because the screen is what an escape sequence inside it would rewrite.

mod input;
mod screen;
mod transcript;
mod view;

pub use input::{Keys, Stopped};
pub use screen::Screen;
pub use transcript::Transcript;
pub use view::Hint;
