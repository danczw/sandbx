//! The tool side of a round: what is offered, and what comes back.
//!
//! The crate's only `spawn_blocking` site. Tools are synchronous, so the sync/async
//! boundary lives here rather than spread through seven tool bodies.

use sandbx_providers::{ContentBlock, ToolDefinition};
use sandbx_tools::{BuiltinTool, ExecutionContext};

use crate::{ApprovalDecision, ToolCall, TurnError};

/// Ask `approve`, then run and answer every tool call in `blocks`, in the order the
/// model asked for them.
///
/// Sequential: concurrency would need the ordering semantics of two tools sharing one
/// `ExecutionContext` settled first (#26).
///
/// `BuiltinTool::execute` may sit in a `write`, a directory walk or a 90-second command,
/// which on a current-thread runtime would freeze every other task — hence
/// `spawn_blocking`, whose uncancellability `run_turn` documents for callers.
pub(super) async fn answer_calls<G>(
    blocks: &[ContentBlock],
    ctx: &ExecutionContext,
    offered: &[BuiltinTool],
    approve: &mut G,
) -> Result<Vec<ContentBlock>, TurnError>
where
    G: FnMut(ToolCall<'_>) -> ApprovalDecision,
{
    let mut results = Vec::new();

    for block in blocks {
        let ContentBlock::ToolUse { id, name, input } = block else {
            continue;
        };

        let Some(tool) = BuiltinTool::from_name(name) else {
            // Lookup is exact by design, so a miss is a prompt or schema bug rather than a
            // near-miss to normalise away. Nothing runs; the model is told which name.
            results.push(refused(id, format!("unknown tool: {name}")));
            continue;
        };

        if !offered.contains(&tool) {
            // `from_name` resolves against every built-in, so resolving alone would hand
            // the gate a call the caller never offered — which an allow-all gate then runs.
            results.push(refused(id, format!("tool not offered this turn: {name}")));
            continue;
        }

        // Before `spawn_blocking`, never racing it: a blocking task cannot be cancelled,
        // so a late decision would not stop the call it refused (#26). Exhaustive rather
        // than `if let`, so a third verdict is a compile error here and not approval.
        match approve(ToolCall { tool, id, input }) {
            ApprovalDecision::Allow => {}
            ApprovalDecision::Deny { reason } => {
                results.push(refused(id, reason));
                continue;
            }
        }

        // Cloned because `spawn_blocking` needs `'static`, once per call because the
        // closure consumes it. An `Arc` would pay off only if `ExecutionContext` grew
        // something costlier than a few path lists.
        let input = input.clone();
        let context = ctx.clone();
        let outcome = tokio::task::spawn_blocking(move || tool.execute(input, &context))
            .await
            .map_err(|_| TurnError::ToolPanicked {
                name: name.to_string(),
            })?;

        results.push(match outcome {
            Ok(output) => ContentBlock::ToolResult {
                tool_use_id: id.clone(),
                content: output.into_content(),
                is_error: None,
            },
            Err(error) => refused(id, error.to_string()),
        });
    }

    Ok(results)
}

/// A tool result the model should read as a failure.
fn refused(id: &str, content: String) -> ContentBlock {
    ContentBlock::ToolResult {
        tool_use_id: id.to_string(),
        content,
        is_error: Some(true),
    }
}

/// Bridge a built-in into the shape a provider request wants.
///
/// No table of its own: `name`, `description` and `input_schema` come from one `SPEC`
/// per tool in `sandbx-tools`, beside the behaviour they describe.
pub(super) fn definition(tool: BuiltinTool) -> ToolDefinition {
    ToolDefinition {
        name: tool.name().to_string(),
        description: tool.description().to_string(),
        input_schema: tool.input_schema(),
    }
}
