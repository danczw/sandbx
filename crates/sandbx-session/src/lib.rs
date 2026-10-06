//! Session persistence: the `SessionStore` that owns a transcript, and the `Session`
//! and `Message` types it stores. Depends on no other sandbx crate.
//!
//! A transcript is append-only JSONL, one record per line, under a directory outside
//! the working tree. Appending is what keeps `withheld` meaningful: it is an index into
//! the history, so a rewrite that moved a prefix would move what it counts.

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
