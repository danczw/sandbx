//! One module per tool, each holding every fact about it: an input struct, an
//! `execute` taking it by value, and a `SPEC` naming the tool and pointing at the
//! fns that build its schema and run it. [`crate::BuiltinTool`] reaches all four
//! through a single match, so they cannot drift apart. A `SPEC` description names
//! the constraint that changes how the tool is called, since a model that learns it
//! from an error has already spent a turn.

pub mod bash;
pub mod edit;
pub mod find;
pub mod grep;
pub mod ls;
pub mod read;
pub mod write;
