//! Session persistence: the `SessionStore` that owns a transcript, and the `Session`
//! and `Message` types it stores. Depends on no other sandbx crate.
//!
//! So far the parts a store is made of: a session's name, which becomes a path
//! component and so is the one value in the crate that must be validated before any
//! I/O; the directory that name is resolved under; and the shape of a stored turn.

mod error;
mod id;
mod message;
mod paths;

pub use error::SessionError;
pub use id::SessionId;
pub use message::{CompletedTurn, Content, Message, Role, Usage};
pub use paths::sessions_directory;
