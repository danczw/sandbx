use std::path::PathBuf;

use serde::Deserialize;

use crate::{ExecutionContext, ToolError, ToolOutput, ToolSpec};

/// This tool, as `BuiltinTool` sees it.
pub(crate) const SPEC: ToolSpec = ToolSpec {
    name: "read",
    description: "Read a file's contents. Takes an absolute path.",
    schema,
    run,
};

/// Argument schema for this tool. Built per call: `schema_for!` allocates, so it
/// cannot be a const value.
fn schema() -> serde_json::Value {
    schemars::schema_for!(ReadInput).to_value()
}

/// Parse untyped arguments into this tool's own input struct, then run it.
fn run(input: serde_json::Value, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    execute(crate::parse(input)?, ctx)
}

/// Arguments for the `read` tool.
///
/// The JSON schema the model is shown is derived from this struct, so the
/// contract advertised and the contract parsed cannot drift apart.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReadInput {
    /// Absolute path of the file to read.
    pub path: PathBuf,
}

/// Read a file's contents.
///
/// Never spawns a process, so the kernel enforcement never sees it — the
/// `FsGuard` check inside [`crate::read_file`] is the only thing keeping it
/// inside the policy.
pub fn execute(input: ReadInput, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    let content = crate::read_file(&input.path, ctx)?;

    Ok(ToolOutput::new(ctx.limits().take_bytes(content)))
}
