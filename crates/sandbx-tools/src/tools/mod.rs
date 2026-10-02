//! One module per tool, each holding every fact about it: an input struct, an
//! `execute` taking that struct by value, and a `SPEC` naming the tool and
//! pointing at the two one-line fns that build its schema and run it.
//! [`crate::BuiltinTool`] reaches all of it through a single match, so the four
//! cannot drift apart the way four parallel matches let them (#55, #88).
//!
//! A `SPEC` description names the constraint that changes how the tool is called
//! — an absolute path, a literal rather than a pattern, a match that must be
//! unique — because a model that learns that from an error has already spent a
//! turn. The rustdoc on `execute` is the *why*, for a reader of the code; the
//! description is the *what*, for a caller of the tool. They say deliberately
//! different things.

pub mod bash;
pub mod edit;
pub mod find;
pub mod grep;
pub mod ls;
pub mod read;
pub mod write;
