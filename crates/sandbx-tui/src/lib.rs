//! Terminal UI: the screen one turn is drawn on, the keys that interrupt it, and the
//! state in between.
//!
//! Takes `&AgentEvent` and hands back a keypress, so a caller keeps the policy, the
//! provider and the session. Model-chosen text is stripped here rather than at the
//! caller: the screen is the thing an escape sequence inside it would rewrite.

mod input;
mod screen;
mod transcript;
mod view;

pub use input::Keys;
pub use screen::Screen;
pub use transcript::Transcript;
pub use view::Hint;
