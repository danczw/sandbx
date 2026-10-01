use std::path::PathBuf;

use serde::Deserialize;

use crate::{ExecutionContext, ToolError, ToolOutput};

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

    Ok(ToolOutput {
        content: ctx.limits().take_bytes(content),
    })
}
