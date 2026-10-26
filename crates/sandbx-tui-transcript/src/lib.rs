//! What one turn shows, and how it is drawn: the event stream folded into entries, and the
//! entries laid out as rows over a status bar.
//!
//! Both halves in one crate because the fold has to strip what the layout draws:
//! `view::GUTTER_MARK` is the view's claim that sandbx wrote a row, and the fold replaces
//! it and its confusables in entry text. Two crates would make that a cycle on one
//! constant, so there is one (#353).
//!
//! No terminal behind either half, which is the point: model-chosen text cannot reach a
//! cell unchanged, and that is a unit test rather than a screenshot.

mod transcript;
mod view;

pub use transcript::Transcript;
pub use view::{Hint, draw};
