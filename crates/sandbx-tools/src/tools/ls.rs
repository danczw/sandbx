use std::path::PathBuf;

use serde::Deserialize;

use crate::{ExecutionContext, ToolError, ToolOutput, ToolSpec};

/// This tool, as `BuiltinTool` sees it.
pub(crate) const SPEC: ToolSpec = ToolSpec {
    name: "ls",
    description: "List a directory's entries. Directories are marked with a trailing slash.",
    schema,
    run,
};

/// Argument schema for this tool. Built per call: `schema_for!` allocates, so it
/// cannot be a const value.
fn schema() -> serde_json::Value {
    schemars::schema_for!(LsInput).to_value()
}

/// Parse untyped arguments into this tool's own input struct, then run it.
fn run(input: serde_json::Value, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    execute(crate::parse(input)?, ctx)
}

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

    // Readdir order is filesystem-dependent; sorting keeps output stable so an
    // unchanged directory does not look different between calls.
    names.sort();

    // Never partial: `ls` reads one directory, so there is no walk to cut off.
    Ok(crate::listing(names, ctx, false))
}
