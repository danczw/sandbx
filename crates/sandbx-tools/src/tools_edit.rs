use std::path::PathBuf;

use serde::Deserialize;

use crate::{ExecutionContext, RiskLevel, ToolError, ToolOutput, ToolSpec};

pub(crate) const SPEC: ToolSpec = ToolSpec {
    name: "edit",
    description: "Replace one exact occurrence of a string in a file. The text \
                  must appear exactly once — an absent or ambiguous match is an \
                  error, not a guess.",
    risk: RiskLevel::Writes,
    schema: || schemars::schema_for!(EditInput).to_value(),
    run: |input, ctx| execute(crate::parse(input)?, ctx),
};

/// Arguments for the `edit` tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct EditInput {
    /// Absolute path of the file to edit.
    pub path: PathBuf,
    /// Exact text to replace. Must appear exactly once.
    pub old: String,
    /// Text to put in its place.
    pub new: String,
}

/// Replace one exact occurrence of a string in a file.
///
/// Read and write are granted independently, so each is checked separately: an edit
/// on a read-only root must fail even though its read half succeeds. An absent or
/// ambiguous match is an error, never a silent no-op — the model otherwise believes
/// the edit happened.
pub(crate) fn execute(input: EditInput, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    use std::io::Write;

    // Read first, where the read half of the policy check lives, so a write-only
    // grant fails before an error message can disclose content.
    let content = crate::read_file(&input.path, ctx)?;

    let occurrences = content.matches(&input.old).count();
    if occurrences != 1 {
        let detail = match occurrences {
            0 => "the text to replace does not appear in the file".to_string(),
            n => format!("the text to replace appears {n} times; it must be unique"),
        };
        return Err(crate::failed("edit", &input.path, detail));
    }

    // The write handle truncates on open, so open only once the match is unique:
    // otherwise a refused edit empties the file it refused to edit.
    let updated = content.replace(&input.old, &input.new);
    let mut target = ctx
        .guard()
        .open_write(&input.path)
        .map_err(|error| crate::guard_error(&input.path, error))?;

    target
        .write_all(updated.as_bytes())
        .map_err(|error| crate::failed("write", &input.path, error))?;

    Ok(ToolOutput::new(format!("edited {}", input.path.display())))
}
