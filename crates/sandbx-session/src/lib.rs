//! Session persistence: the `SessionStore` that owns a transcript, and the `Session` it
//! hands back. The shapes it stores are `sandbx-session-message`'s.
//!
//! A transcript is append-only JSONL, never rewritten (see
//! `context/decision-on-disk-state.md`). `SessionStore::new` takes whatever root it is
//! handed, so keeping that root outside the working tree is `sandbx-session-paths`' and not
//! enforced here. Nothing here expires or redacts a transcript, and it holds whatever a
//! tool read into the conversation; see `SECURITY.md`.

mod store;

pub use store::{Session, SessionStore};
