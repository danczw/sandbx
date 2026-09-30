//! The agent loop: drives a provider's streamed turn, routes a requested tool
//! call through an approval gate before `sandbx-tools` executes it, persists the
//! transcript through `SessionStore`, and compacts it once it outgrows the
//! context window.
//!
//! Placeholder — nothing is implemented yet. It is meant to stay UI- and
//! provider-agnostic, so the whole loop can be driven end to end against a
//! mock provider and a temp-dir tool registry, with no network access and no
//! unsandboxed execution.
