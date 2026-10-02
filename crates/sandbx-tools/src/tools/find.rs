use std::path::PathBuf;

use serde::Deserialize;

use crate::{ExecutionContext, ToolError, ToolOutput, ToolSpec};

/// This tool, as `BuiltinTool` sees it.
pub(crate) const SPEC: ToolSpec = ToolSpec {
    name: "find",
    description: "Find files beneath a directory whose name contains a substring.",
    schema,
    run,
};

/// Argument schema for this tool. Built per call: `schema_for!` allocates, so it
/// cannot be a const value.
fn schema() -> serde_json::Value {
    schemars::schema_for!(FindInput).to_value()
}

/// Parse untyped arguments into this tool's own input struct, then run it.
fn run(input: serde_json::Value, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    execute(crate::parse(input)?, ctx)
}

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
    let walk = ctx
        .guard()
        .walk_readable(&input.path, ctx.limits().max_files_scanned())
        .map_err(|error| crate::denied(&input.path, error))?;

    // Matched against the name being reported, not the name it was reached by:
    // reporting one path while having matched a different one gives the model a
    // result whose filename does not contain what it searched for.
    let found = walk
        .files
        .into_iter()
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().contains(&input.name))
        })
        .map(|path| path.display().to_string())
        .collect();

    Ok(crate::listing(found, ctx, walk.truncated))
}
