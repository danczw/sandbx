use std::path::PathBuf;

use serde::Deserialize;

use crate::{ExecutionContext, RiskLevel, ToolError, ToolOutput, ToolSpec};

pub(crate) const SPEC: ToolSpec = ToolSpec {
    name: "find",
    description: "Find files beneath a directory whose name contains a substring.",
    risk: RiskLevel::ReadOnly,
    schema,
    run,
};

fn schema() -> serde_json::Value {
    schemars::schema_for!(FindInput).to_value()
}

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

    // Matched against the name being reported, not the one it was reached by: the
    // model would otherwise get hits whose filename lacks what it searched for.
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
