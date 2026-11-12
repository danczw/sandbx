//! The tool side of a round: what is offered, and what comes back.
//!
//! The crate's only `spawn_blocking` site. Tools are synchronous, so the sync/async
//! boundary lives here rather than spread through seven tool bodies.

use sandbx_approval::{ApprovalDecision, CallGate, Outcome, Settled, ToolCall};
use sandbx_prompt::{ContentBlock, ToolDefinition};
use sandbx_tools::{BuiltinTool, ExecutionContext, ToolError};

use crate::TurnError;

/// Ask `gate`, then run and answer every tool call in `blocks`, in the order the model asked.
///
/// Sequential: concurrency would need the ordering semantics of two tools sharing one
/// `ExecutionContext` settled first (#242). `BuiltinTool::execute` may sit in a `write`, a
/// directory walk or a 90-second command, which on a current-thread runtime would freeze
/// every other task — hence `spawn_blocking`, whose uncancellability `run_turn` documents.
/// Every answered block reports to [`CallGate::settled`], including the two refusals above
/// the gate, which the gate's own verdict cannot account for.
///
/// A cancelled `ctx` ends the loop early, leaving a `tool_use` with no `tool_result`: the
/// caller must drop the round, which `run_turn_until` does and is the only caller to hold
/// the token.
pub(crate) async fn answer_calls<G>(
    blocks: &[ContentBlock],
    ctx: &ExecutionContext,
    offered: &[BuiltinTool],
    gate: &mut G,
) -> Result<Answers, TurnError>
where
    G: CallGate,
{
    let mut results = Vec::new();
    // Set by the first `Abort`: the gate can no longer decide, so a later call isn't a
    // later decision to ask for.
    let mut aborted: Option<String> = None;

    for block in blocks {
        // Nothing behind a stopped call is asked about or run.
        if ctx.cancelled() {
            break;
        }

        let ContentBlock::ToolUse { id, name, input } = block else {
            continue;
        };
        let settle = |tool, outcome| Settled {
            name,
            id,
            tool,
            input,
            outcome,
        };

        let Some(tool) = BuiltinTool::from_name(name) else {
            // Lookup is exact by design: a miss is a prompt or schema bug, not a near-miss
            // to normalise. Nothing runs; the model is told which name.
            gate.settled(settle(None, Outcome::Unknown));
            results.push(refused(id, format!("unknown tool: {name}")));
            continue;
        };

        if !offered.contains(&tool) {
            // `from_name` resolves against every built-in, so resolving alone would hand the
            // gate a call the caller never offered — which an allow-all gate then runs.
            gate.settled(settle(Some(tool), Outcome::NotOffered));
            results.push(refused(id, format!("tool not offered this turn: {name}")));
            continue;
        }

        // Before `spawn_blocking`, never racing it: an in-process tool cannot be cancelled,
        // so a late decision would not stop the call it refused (#26).
        let verdict = match &aborted {
            Some(reason) => ApprovalDecision::Deny {
                reason: reason.clone(),
            },
            None => gate.approve(ToolCall { tool, id, input }),
        };

        // Exhaustive rather than `if let`, so a fourth verdict is a compile error, not approval.
        match verdict {
            ApprovalDecision::Allow => {}
            ApprovalDecision::Deny { reason } => {
                gate.settled(settle(Some(tool), Outcome::Denied { reason: &reason }));
                results.push(refused(id, reason));
                continue;
            }
            // Answered, not skipped: a `tool_use` with no `tool_result` is a transcript no
            // provider takes back, and this one is stored and resumed.
            ApprovalDecision::Abort { reason } => {
                gate.settled(settle(Some(tool), Outcome::Denied { reason: &reason }));
                results.push(refused(id, reason.clone()));
                aborted = Some(reason);
                continue;
            }
        }

        // Cloned because `spawn_blocking` needs `'static`, once per call since the closure
        // consumes it; an `Arc` would only pay off past a few path lists.
        let arguments = input.clone();
        let context = ctx.clone();
        let outcome = tokio::task::spawn_blocking(move || tool.execute(arguments, &context))
            .await
            .map_err(|_| TurnError::ToolPanicked {
                name: name.to_string(),
            })?;

        // Read after the join, never before the spawn: a call that finished a moment before
        // the stop is withheld too, which errs toward saying less of what the operator stopped.
        let stopped = ctx.cancelled();
        results.push(match outcome {
            Ok(output) => {
                gate.settled(settle(Some(tool), Outcome::Ran));
                if stopped {
                    refused(id, FINISHED_AFTER_STOP.to_string())
                } else {
                    ContentBlock::ToolResult {
                        tool_use_id: id.clone(),
                        content: output.into_content(),
                        is_error: None,
                    }
                }
            }
            Err(error) => {
                gate.settled(settle(Some(tool), Outcome::Errored(&error)));
                match (stopped, &error) {
                    (false, _) => refused(id, error.to_string()),
                    (true, ToolError::Cancelled { .. }) => refused(id, CANCELLED.to_string()),
                    (true, _) => refused(id, FINISHED_AFTER_STOP.to_string()),
                }
            }
        });
    }

    // A stop ends the loop above early. Answered here, in the order asked, because a
    // `tool_use` with no `tool_result` is a transcript no provider takes back, and a
    // stopped round is stored and resumed.
    // By position and not by id: each call leaves exactly one result, in order, so the
    // unanswered are the suffix.
    let behind: Vec<&String> = blocks
        .iter()
        .filter_map(|block| match block {
            ContentBlock::ToolUse { id, .. } => Some(id),
            _ => None,
        })
        .skip(results.len())
        .collect();
    results.extend(
        behind
            .into_iter()
            .map(|id| refused(id, NOT_RUN.to_string())),
    );

    Ok(Answers {
        results,
        aborted: aborted.is_some(),
    })
}

/// One round's answers, and whether the gate ended the turn giving them.
pub(crate) struct Answers {
    /// One `tool_result` per `tool_use` block, in the order the model asked.
    pub(crate) results: Vec<ContentBlock>,

    /// Whether an [`ApprovalDecision::Abort`] stopped the round, so no later round runs.
    pub(crate) aborted: bool,
}

// What a stopped round stores in place of a call's own result. Fixed text and never a
// path, a command or a tool's output: a resume sends these to the provider, and the
// operator stopped before reading any of it.

/// A call behind the one the stop landed on, never put to the gate or run.
const NOT_RUN: &str = "not run: the turn was stopped";

/// A call the stop killed or interrupted before it could finish.
const CANCELLED: &str = "cancelled: the turn was stopped before it finished";

/// A call that finished once the stop was raised. Says its effect stands, because a `write`
/// that landed and was recorded as not run would be done again.
const FINISHED_AFTER_STOP: &str = "was running when the turn was stopped; it finished, its \
                                   effect stands, its output was withheld";

fn refused(id: &str, content: String) -> ContentBlock {
    ContentBlock::ToolResult {
        tool_use_id: id.to_string(),
        content,
        is_error: Some(true),
    }
}

/// Bridge a built-in into the shape a provider request wants.
///
/// No table of its own: all three fields come from one `SPEC` per tool in `sandbx-tools`,
/// beside the behaviour they describe.
pub(crate) fn definition(tool: BuiltinTool) -> ToolDefinition {
    ToolDefinition {
        name: tool.name().to_string(),
        description: tool.description().to_string(),
        schema: tool.input_schema(),
    }
}
