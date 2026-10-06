//! Session persistence: the `SessionStore` that owns a transcript, and the `Session`
//! and `Message` types it stores. Depends on no other sandbx crate.
//!
//! So far only the id: a session's name, which becomes a path component and so is the
//! one value in the crate that must be validated before any I/O.

mod error;
mod id;

pub use error::SessionError;
pub use id::SessionId;
