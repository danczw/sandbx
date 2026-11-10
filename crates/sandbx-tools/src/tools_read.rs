use std::path::PathBuf;

use serde::Deserialize;

use crate::{ExecutionContext, RiskLevel, ToolError, ToolOutput, ToolSpec};

pub(crate) const SPEC: ToolSpec = ToolSpec {
    name: "read",
    description: "Read a file's contents. Takes an absolute path.",
    risk: RiskLevel::ReadOnly,
    schema: || schemars::schema_for!(ReadInput).to_value(),
    run: |input, ctx| execute(crate::parse(input)?, ctx),
};

/// Arguments for the `read` tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct ReadInput {
    /// Absolute path of the file to read.
    pub path: PathBuf,
}

/// Read a file's contents.
///
/// Never spawns, so the kernel enforcement never sees it: the `FsGuard` check
/// inside [`crate::read_head`] is the only thing holding it inside the policy.
pub(crate) fn execute(input: ReadInput, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    let max = ctx.limits().max_bytes() as u64;
    let (mut head, cut) = crate::read_head(&input.path, ctx, max)?;

    if let crate::Cut::Short { total } = cut {
        let marker = crate::byte_marker(head.len(), total);
        // Exact: the head can fill its buffer, which a plain push would double.
        head.reserve_exact(marker.len());
        head.push_str(&marker);
    }
    Ok(ToolOutput::new(head))
}
