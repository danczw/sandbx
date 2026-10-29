//! One module per tool, each holding every fact about it: an input struct, an
//! `execute` taking it by value, and a `SPEC` naming the tool and pointing at the
//! fns that build its schema and run it. [`crate::BuiltinTool`] reaches all four
//! through a single match, so they cannot drift apart. A `SPEC` description names
//! the constraint that changes how the tool is called, since a model that learns it
//! from an error has already spent a turn.

#[path = "tools_bash.rs"]
pub(crate) mod bash;
#[path = "tools_edit.rs"]
pub(crate) mod edit;
#[path = "tools_find.rs"]
pub(crate) mod find;
#[path = "tools_grep.rs"]
pub(crate) mod grep;
#[path = "tools_ls.rs"]
pub(crate) mod ls;
#[path = "tools_read.rs"]
pub(crate) mod read;
#[path = "tools_write.rs"]
pub(crate) mod write;
