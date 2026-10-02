use std::path::PathBuf;

use serde::Deserialize;

use crate::{ExecutionContext, ToolError, ToolOutput};

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
