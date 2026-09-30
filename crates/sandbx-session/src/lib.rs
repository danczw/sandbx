//! Session persistence: the `SessionStore` trait, and the `Session` and
//! `Message` types it stores.
//!
//! Placeholder — nothing is implemented yet. The first store will be a
//! `FileSessionStore` over `serde_json`, which adds no runtime dependency; a
//! `redb`-backed one follows only if persistence has to scale past that. This
//! crate deliberately depends on no other sandbx crate, so the transcript
//! format and the agent loop can move independently.
