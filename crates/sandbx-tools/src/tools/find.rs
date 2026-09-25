use std::path::PathBuf;

use serde::Deserialize;

use crate::{ExecutionContext, ToolError, ToolOutput};

/// Arguments for the `find` tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FindInput {
    /// Absolute path of the directory to search.
    pub path: PathBuf,
    /// Substring to match against file names.
    pub name: String,
}

/// Find files beneath a directory whose name contains a substring.
pub fn execute(input: FindInput, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    let files = ctx
        .guard()
        .walk_readable(&input.path)
        .map_err(crate::denied(&input.path))?;

    // Matched against the name being reported, not the name it was reached by:
    // reporting one path while having matched a different one gives the model a
    // result whose filename does not contain what it searched for.
    let found = files
        .into_iter()
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().contains(&input.name))
        })
        .map(|path| path.display().to_string())
        .collect();

    Ok(crate::listing(found, ctx))
}
