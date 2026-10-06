//! Session persistence: the `SessionStore` that owns a transcript, and the `Session`
//! and `Message` types it stores. Depends on no other sandbx crate.
//!
//! So far the id and the root: a session's name, which becomes a path component and so
//! is the one value in the crate that must be validated before any I/O, and the
//! directory that name is resolved under.

mod error;
mod id;
mod paths;

pub use error::SessionError;
pub use id::SessionId;
pub use paths::sessions_directory;
