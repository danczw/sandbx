use std::path::PathBuf;

use serde::Deserialize;

use crate::{ExecutionContext, ToolError, ToolOutput, ToolSpec};

/// This tool, as `BuiltinTool` sees it.
pub(crate) const SPEC: ToolSpec = ToolSpec {
    name: "write",
    description: "Write a file, creating it or replacing its contents entirely. \
                  Takes an absolute path.",
    schema,
    run,
};

/// Argument schema for this tool. Built per call: `schema_for!` allocates, so it
/// cannot be a const value.
fn schema() -> serde_json::Value {
    schemars::schema_for!(WriteInput).to_value()
}

/// Parse untyped arguments into this tool's own input struct, then run it.
fn run(input: serde_json::Value, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    execute(crate::parse(input)?, ctx)
}

/// Arguments for the `write` tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WriteInput {
    /// Absolute path of the file to write. Created if it does not exist.
    pub path: PathBuf,
    /// Full contents to write, replacing anything already there.
    pub content: String,
}

/// Write a file, creating or replacing it.
///
/// In-process, so `FsGuard` is the only confinement. It also rejects a symlink
/// leaf, which matters here: the agent can plant symlinks in any writable root,
/// and following one would land the write outside the policy.
pub fn execute(input: WriteInput, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    let mut file = ctx
        .guard()
        .open_write(&input.path)
        .map_err(|error| crate::denied(&input.path, error))?;

    std::io::Write::write_all(&mut file, input.content.as_bytes())
        .map_err(|error| crate::failed("write", &input.path, error))?;

    Ok(ToolOutput::new(format!(
        "wrote {} bytes to {}",
        input.content.len(),
        input.path.display()
    )))
}
