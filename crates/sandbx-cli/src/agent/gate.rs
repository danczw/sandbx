//! Which tools this run approved, and what the model is told about the rest.
//!
//! Its own module because it changes for a different reason than the rest of `agent-run`:
//! who may approve a call and when, which is still open (#165). The decision here is
//! taken from argv alone, before the first request goes out.

use sandbx_agent::{ApprovalDecision, ToolCall};
use sandbx_tools::{BuiltinTool, RiskLevel};

/// The flag that lifts the default refusal.
///
/// Named once because a refusal is read twice — on stderr and in the `tool_result` — and
/// the two accounts must not advise differently.
pub(super) const ALLOW_TOOL: &str = "--allow-tool";

/// Whether the model may call `tool` in this run.
///
/// `allowed` is `--allow-tool` as clap parsed it: absent, bare, or a list. Fail-closed,
/// there being no operator to ask: a tool that does more than read runs only when a flag
/// named it, or when the bare flag approved every tool.
pub(super) fn approves(allowed: Option<&[BuiltinTool]>, tool: BuiltinTool) -> bool {
    if tool.risk() == RiskLevel::ReadOnly {
        return true;
    }

    match allowed {
        None => false,
        // An empty `Vec` is the bare flag, so `--allow-tool --allow-tool write` approves
        // `write` alone: the broader spelling yields the narrower set.
        Some([]) => true,
        Some(named) => named.contains(&tool),
    }
}

/// The tools this run approved, in `BuiltinTool::ALL` order.
///
/// Reported before the first request, the fail-open spelling being a typo away: clap
/// reads `--allow-tool -- write the file` as the bare flag plus a prompt, which the
/// per-call lines would not show until a `bash` ran.
pub(super) fn approved_tools(allowed: Option<&[BuiltinTool]>) -> Vec<&'static str> {
    BuiltinTool::ALL
        .iter()
        .filter(|tool| approves(allowed, **tool))
        .map(|tool| tool.name())
        .collect()
}

/// The decision for one call, and the operator's line about it.
///
/// Printed here and not from `observe`, which fires while the round is still streaming
/// and so would announce a call this then refuses.
pub(super) fn decide(allowed: Option<&[BuiltinTool]>, requested: ToolCall<'_>) -> ApprovalDecision {
    let name = requested.tool.name();

    if approves(allowed, requested.tool) {
        eprintln!("sandbx: running {name}");
        return ApprovalDecision::Allow;
    }

    eprintln!("sandbx: refused {name}, which needs `{ALLOW_TOOL} {name}`");
    ApprovalDecision::Deny {
        reason: format!(
            "the `{name}` tool is not approved for this run: \
             it runs only when sandbx is started with `{ALLOW_TOOL} {name}`"
        ),
    }
}

/// Accept a tool `--allow-tool` can actually approve, and refuse anything else.
///
/// `BuiltinTool::from_name` is exact-match, so taking a near miss would approve nothing
/// and exit 0, leaving whoever typed `--allow-tool shell` believing `bash` was approved.
pub(super) fn tool_name(value: &str) -> Result<BuiltinTool, String> {
    BuiltinTool::from_name(value).ok_or_else(|| {
        // Only the tools the flag can change: listing all seven would invite
        // `--allow-tool read`, which parses and widens nothing.
        let names: Vec<&str> = BuiltinTool::ALL
            .iter()
            .filter(|tool| tool.risk() != RiskLevel::ReadOnly)
            .map(|tool| tool.name())
            .collect();
        format!(
            "no tool is called `{value}`; the tools needing approval are {}",
            names.join(", ")
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use clap::Parser;

    /// Driven through argv rather than a hand-built list: the three states are clap's
    /// reading of the flag, and that reading is half of what these tests pin.
    fn allowed(argv: &[&str]) -> Option<Vec<BuiltinTool>> {
        match crate::Cli::parse_from(argv).command {
            crate::Command::AgentRun(args) => args.allow_tool,
            other => panic!("{other:?} is not agent-run"),
        }
    }

    /// Spelled out rather than compared against `risk()`, the table `approves` itself
    /// reads: derived, a `bash` reclassified as read-only would pass while running.
    #[test]
    fn the_read_only_tools_need_no_flag() {
        let allowed = allowed(&["sandbx", "agent-run", "--", "hello"]);
        let allowed = allowed.as_deref();

        assert!(approves(allowed, BuiltinTool::Read));
        assert!(approves(allowed, BuiltinTool::Ls));
        assert!(approves(allowed, BuiltinTool::Grep));
        assert!(approves(allowed, BuiltinTool::Find));
        assert!(!approves(allowed, BuiltinTool::Write));
        assert!(!approves(allowed, BuiltinTool::Edit));
        assert!(!approves(allowed, BuiltinTool::Bash));
    }

    #[test]
    fn a_named_tool_is_the_only_one_lifted() {
        let allowed = allowed(&["sandbx", "agent-run", "--allow-tool", "write", "--", "go"]);
        let allowed = allowed.as_deref();

        assert!(approves(allowed, BuiltinTool::Write));
        assert!(!approves(allowed, BuiltinTool::Edit));
        assert!(!approves(allowed, BuiltinTool::Bash));
        assert!(approves(allowed, BuiltinTool::Read), "a read was withdrawn");
    }

    #[test]
    fn a_bare_allow_tool_approves_every_tool() {
        let allowed = allowed(&["sandbx", "agent-run", "--allow-tool", "--", "go"]);

        for tool in BuiltinTool::ALL {
            assert!(
                approves(allowed.as_deref(), tool),
                "{tool:?} is refused under the bare flag"
            );
        }
    }

    /// The broader spelling yields the narrower set, as `--allow-network` does.
    #[test]
    fn mixing_a_bare_flag_with_a_tool_narrows_to_the_tool() {
        let allowed = allowed(&[
            "sandbx",
            "agent-run",
            "--allow-tool",
            "--allow-tool",
            "write",
            "--",
            "go",
        ]);
        let allowed = allowed.as_deref();

        assert!(approves(allowed, BuiltinTool::Write));
        assert!(!approves(allowed, BuiltinTool::Bash));
    }

    /// A misplaced `--` turns `--allow-tool write -- "…"` into the bare flag plus a
    /// prompt, approving all seven — which the announced set shows before a `bash` runs.
    #[test]
    fn a_bare_flag_from_a_misplaced_separator_announces_all_seven() {
        let allowed = allowed(&["sandbx", "agent-run", "--allow-tool", "--", "write", "it"]);

        assert_eq!(
            approved_tools(allowed.as_deref()),
            ["read", "write", "bash", "edit", "ls", "grep", "find"],
            "the bare flag approved something other than every tool"
        );
    }

    /// The line a default run prints: the four that need no flag, and nothing else.
    #[test]
    fn the_announced_set_is_the_read_only_four_by_default() {
        let allowed = allowed(&["sandbx", "agent-run", "--", "go"]);

        assert_eq!(
            approved_tools(allowed.as_deref()),
            ["read", "ls", "grep", "find"]
        );
    }

    /// The `tool_result` is the only account the model gets, so saying no is not enough.
    #[test]
    fn a_refusal_tells_the_model_which_flag_would_lift_it() {
        let input = serde_json::Value::Null;

        let ApprovalDecision::Deny { reason } = decide(
            None,
            ToolCall {
                tool: BuiltinTool::Bash,
                id: "call_1",
                input: &input,
            },
        ) else {
            panic!("bash was approved with no flag");
        };

        assert!(reason.contains("`--allow-tool bash`"), "got {reason}");
    }

    #[test]
    fn an_approved_tool_is_allowed_not_merely_announced() {
        let allowed = allowed(&["sandbx", "agent-run", "--allow-tool", "bash", "--", "go"]);
        let input = serde_json::Value::Null;

        let decision = decide(
            allowed.as_deref(),
            ToolCall {
                tool: BuiltinTool::Bash,
                id: "call_1",
                input: &input,
            },
        );

        assert_eq!(decision, ApprovalDecision::Allow);
    }

    /// `--allow-tool` can only widen, so offering a read-only name back would invite a
    /// spelling that parses and changes nothing.
    #[test]
    fn the_unknown_name_advice_lists_only_what_needs_approving() {
        let message = tool_name("shell").expect_err("a name no tool answers to was accepted");

        assert!(message.contains("write"), "got {message}");
        assert!(message.contains("bash"), "got {message}");
        assert!(
            !message.contains("grep"),
            "a read-only tool was offered as approvable: {message}"
        );
    }
}
