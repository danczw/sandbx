use std::path::PathBuf;

use serde::Deserialize;

use crate::{ExecutionContext, ToolError, ToolOutput};

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
        .map_err(crate::denied(&input.path))?;

    std::io::Write::write_all(&mut file, input.content.as_bytes()).map_err(|error| {
        ToolError::Failed {
            subject: format!("write {}", input.path.display()),
            detail: error.to_string(),
        }
    })?;

    Ok(ToolOutput {
        content: format!(
            "wrote {} bytes to {}",
            input.content.len(),
            input.path.display()
        ),
    })
}
