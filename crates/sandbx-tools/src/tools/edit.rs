use std::path::PathBuf;

use serde::Deserialize;

use crate::{ExecutionContext, ToolError, ToolOutput, ToolSpec};

/// This tool, as `BuiltinTool` sees it.
pub(crate) const SPEC: ToolSpec = ToolSpec {
    name: "edit",
    description: "Replace one exact occurrence of a string in a file. The text \
                  must appear exactly once — an absent or ambiguous match is an \
                  error, not a guess.",
    schema,
    run,
};

/// Argument schema for this tool. Built per call: `schema_for!` allocates, so it
/// cannot be a const value.
fn schema() -> serde_json::Value {
    schemars::schema_for!(EditInput).to_value()
}

/// Parse untyped arguments into this tool's own input struct, then run it.
fn run(input: serde_json::Value, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    execute(crate::parse(input)?, ctx)
}

/// Arguments for the `edit` tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EditInput {
    /// Absolute path of the file to edit.
    pub path: PathBuf,
    /// Exact text to replace. Must appear exactly once.
    pub old: String,
    /// Text to put in its place.
    pub new: String,
}

/// Replace one exact occurrence of a string in a file.
///
/// Requires the path to be both readable and writable, and checks each
/// separately — the policy grants them independently, so an edit on a read-only
/// root must fail even though the read half would succeed.
///
/// A match that is absent or ambiguous is an error, never a silent no-op or a
/// guess: the model believes the edit happened, so getting it wrong quietly is
/// worse than failing.
pub fn execute(input: EditInput, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    // Read first — through [`crate::read_file`], which is where the read half of
    // the policy check lives — so a read-only grant fails before any content is
    // disclosed through an error message.
    let content = crate::read_file(&input.path, ctx)?;

    let occurrences = content.matches(&input.old).count();
    if occurrences != 1 {
        return Err(ToolError::Failed {
            subject: format!("edit {}", input.path.display()),
            detail: match occurrences {
                0 => "the text to replace does not appear in the file".to_string(),
                n => format!("the text to replace appears {n} times; it must be unique"),
            },
        });
    }

    // Opened only once the replacement is known to be unambiguous, so a failed
    // edit never truncates the file it could not edit.
    let updated = content.replace(&input.old, &input.new);
    let mut target = ctx
        .guard()
        .open_write(&input.path)
        .map_err(|error| crate::denied(&input.path, error))?;

    std::io::Write::write_all(&mut target, updated.as_bytes())
        .map_err(|error| crate::failed("write", &input.path, error))?;

    Ok(ToolOutput::new(format!("edited {}", input.path.display())))
}
