use std::path::PathBuf;

use serde::Deserialize;

use crate::{ExecutionContext, RiskLevel, ToolError, ToolOutput, ToolSpec};

pub(crate) const SPEC: ToolSpec = ToolSpec {
    name: "ls",
    description: "List a directory's entries. Directories are marked with a trailing slash.",
    risk: RiskLevel::ReadOnly,
    schema: || schemars::schema_for!(LsInput).to_value(),
    run: |input, ctx| execute(crate::parse(input)?, ctx),
};

/// Arguments for the `ls` tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct LsInput {
    /// Absolute path of the directory to list.
    pub path: PathBuf,
}

/// List a directory's entries, marking directories with a trailing `/` so the model
/// need not spend a call per entry to find what it can descend into.
pub(crate) fn execute(input: LsInput, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    let listing = ctx
        .guard()
        .read_dir(&input.path)
        .map_err(|error| crate::guard_error(&input.path, error))?
        .map_err(|error| crate::failed("list", &input.path, error))?;

    let mut names: Vec<String> = listing
        .entries
        .into_iter()
        .map(|entry| {
            let name = entry.name.to_string_lossy().into_owned();
            match entry.directory {
                true => format!("{name}/"),
                false => name,
            }
        })
        .collect();

    // Readdir order is filesystem-dependent: sort so an unchanged directory does
    // not read differently between calls.
    names.sort();

    // Never partial: `ls` reads one directory, so there is no walk to cut off.
    Ok(crate::listing(names, ctx, false))
}
