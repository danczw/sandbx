use std::path::PathBuf;

use serde::Deserialize;

use crate::{ExecutionContext, RiskLevel, ToolError, ToolOutput, ToolSpec};

pub(crate) const SPEC: ToolSpec = ToolSpec {
    name: "ls",
    description: "List a directory's entries. Directories are marked with a trailing slash.",
    risk: RiskLevel::ReadOnly,
    schema,
    run,
};

fn schema() -> serde_json::Value {
    schemars::schema_for!(LsInput).to_value()
}

fn run(input: serde_json::Value, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    execute(crate::parse(input)?, ctx)
}

/// Arguments for the `ls` tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LsInput {
    /// Absolute path of the directory to list.
    pub path: PathBuf,
}

/// List a directory's entries, marking directories with a trailing `/` so the model
/// need not spend a call per entry to find what it can descend into.
pub fn execute(input: LsInput, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    let resolved = ctx
        .guard()
        .check_read(&input.path)
        .map_err(|error| crate::denied(&input.path, error))?;

    let entries =
        std::fs::read_dir(&resolved).map_err(|error| crate::failed("list", &input.path, error))?;

    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| crate::failed("list", &input.path, error))?;
        let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
        let name = entry.file_name().to_string_lossy().into_owned();
        names.push(if is_dir { format!("{name}/") } else { name });
    }

    // Readdir order is filesystem-dependent: sort so an unchanged directory does
    // not read differently between calls.
    names.sort();

    // Never partial: `ls` reads one directory, so there is no walk to cut off.
    Ok(crate::listing(names, ctx, false))
}
