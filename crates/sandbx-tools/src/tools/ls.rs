use std::path::PathBuf;

use serde::Deserialize;

use crate::{ExecutionContext, ToolError, ToolOutput};

/// Arguments for the `ls` tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LsInput {
    /// Absolute path of the directory to list.
    pub path: PathBuf,
}

/// List a directory's entries.
///
/// Directories carry a trailing `/` so the model can tell what it may descend
/// into without a second call per entry.
pub fn execute(input: LsInput, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    let resolved = ctx
        .guard()
        .check_read(&input.path)
        .map_err(crate::denied(&input.path))?;

    let entries = std::fs::read_dir(&resolved).map_err(|error| ToolError::Failed {
        subject: format!("list {}", input.path.display()),
        detail: error.to_string(),
    })?;

    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| ToolError::Failed {
            subject: format!("list {}", input.path.display()),
            detail: error.to_string(),
        })?;
        let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
        let name = entry.file_name().to_string_lossy().into_owned();
        names.push(if is_dir { format!("{name}/") } else { name });
    }

    // Readdir order is filesystem-dependent; sorting keeps output stable so an
    // unchanged directory does not look different between calls.
    names.sort();

    Ok(crate::listing(names, ctx))
}
