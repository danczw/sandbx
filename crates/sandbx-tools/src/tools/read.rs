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
/// `FsGuard` check below is the only thing keeping it inside the policy.
pub fn execute(input: ReadInput, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    // An open handle rather than a path: a path would be re-resolved when
    // opened, leaving a window for the leaf to be swapped for a symlink after
    // the policy check.
    let mut file = ctx
        .guard()
        .open_read(&input.path)
        .map_err(crate::denied(&input.path))?;

    let mut content = String::new();
    std::io::Read::read_to_string(&mut file, &mut content).map_err(|error| ToolError::Failed {
        subject: format!("read {}", input.path.display()),
        detail: error.to_string(),
    })?;

    Ok(ToolOutput {
        content: ctx.limits().take_bytes(content),
    })
}
