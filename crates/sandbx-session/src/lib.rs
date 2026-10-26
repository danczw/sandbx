//! Session persistence: the `SessionStore` that owns a transcript, and the `Session` it
//! hands back. The shapes it stores are `sandbx-session-message`'s.
//!
//! A transcript is append-only JSONL outside the working tree, never rewritten (see
//! `context/decision-on-disk-state.md`). Nothing here expires or redacts one, and it
//! holds whatever a tool read into the conversation; see `SECURITY.md`.

mod error;
mod id;
mod paths;
mod store;

pub use error::SessionError;
pub use id::SessionId;
pub use paths::sessions_directory;
pub use store::{Session, SessionStore};
