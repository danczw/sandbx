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
    let (mut head, cut) = crate::read_head(&input.path, ctx, ctx.limits().max_bytes() as u64)?;

    // `ToolLimits::cap_bytes`'s marker, for a head the read already cut.
    let shown = head.len();
    let showing = match cut {
        crate::Cut::Whole => return Ok(ToolOutput::new(head)),
        crate::Cut::Short { total: Some(total) } => format!("{shown} of {total} bytes"),
        crate::Cut::Short { total: None } => format!("the first {shown} bytes"),
    };
    head.push_str(&format!("\n... truncated: showing {showing}"));

    Ok(ToolOutput::new(head))
}
