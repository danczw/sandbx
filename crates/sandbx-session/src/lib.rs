//! Session persistence: the `SessionStore` that owns a transcript, and the `Session`
//! and `Message` types it stores. Depends on no other sandbx crate.
//!
//! A transcript is append-only JSONL, one record per line, under a directory outside the
//! working tree. See `context/decision-on-disk-state.md` for why it is never rewritten.

mod error;
mod id;
mod message;
mod paths;
mod store;

pub use error::SessionError;
pub use id::SessionId;
pub use message::{CompletedTurn, Content, Message, Role, Usage};
pub use paths::sessions_directory;
pub use store::{Session, SessionStore};
