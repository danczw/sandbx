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

/// A consent channel that answers whatever it is told to, and counts being asked.
struct Asked {
    answer: ApprovalDecision,
    count: usize,
}

impl Ask for Asked {
    fn ask(&mut self, _: ToolCall<'_>) -> ApprovalDecision {
        self.count += 1;
        self.answer.clone()
    }
}

/// The verdict for one call under one argv, with arguments the model might have sent.
fn verdict(argv: &[&str], tool: BuiltinTool, input: &serde_json::Value) -> ApprovalDecision {
    let allowed = allowed(argv);
    ArgvGate::<Asked>::new(allowed.as_deref(), None).approve(ToolCall {
        tool,
        id: "call_1",
        input,
    })
}

/// The verdict for one call under one argv, with an operator giving `answer`, and how
/// many times that operator was asked.
fn asked(argv: &[&str], tool: BuiltinTool, answer: ApprovalDecision) -> (ApprovalDecision, usize) {
    let allowed = allowed(argv);
    let input = serde_json::json!({ "path": "/work/out.rs" });
    let mut gate = ArgvGate::new(allowed.as_deref(), Some(Asked { answer, count: 0 }));

    let decision = gate.approve(ToolCall {
        tool,
        id: "call_1",
        input: &input,
    });

    (
        decision,
        gate.terminal.expect("the channel is still there").count,
    )
}

/// A prompt that could only ever be refused is fatigue with no decision in it, and it
/// would teach an operator to answer `y` to everything.
#[test]
fn a_tool_argv_never_approved_is_refused_without_asking() {
    let (decision, count) = asked(
        &["sandbx", "agent-run", "--", "go"],
        BuiltinTool::Bash,
        ApprovalDecision::Allow,
    );

    assert_eq!(
        count, 0,
        "an operator was asked to grant what argv withheld"
    );
    let ApprovalDecision::Deny { reason } = decision else {
        panic!("bash ran under an answer the ceiling had already refused");
    };
    assert!(reason.contains("`--allow-tool bash`"), "got {reason}");
}

/// Twenty prompts in one turn is what #165 describes; a `read` has no answer worth taking.
#[test]
fn a_read_only_call_is_not_asked_about() {
    let (decision, count) = asked(
        &["sandbx", "agent-run", "--approve", "call", "--", "go"],
        BuiltinTool::Grep,
        ApprovalDecision::Deny {
            reason: "refused".to_owned(),
        },
    );

    assert_eq!(decision, ApprovalDecision::Allow);
    assert_eq!(count, 0, "a read-only call was put to the operator");
}

/// The flag is the ceiling and the operator is the floor: a tool argv approved still runs
/// only if the one call was.
#[test]
fn an_operator_can_refuse_what_argv_approved() {
    let argv = &["sandbx", "agent-run", "--allow-tool", "write", "--", "go"];
    let refusal = ApprovalDecision::Deny {
        reason: "the operator refused this call".to_owned(),
    };

    let (denied, asked_once) = asked(argv, BuiltinTool::Write, refusal.clone());
    assert_eq!(denied, refusal);
    assert_eq!(asked_once, 1, "the call was decided without the operator");

    // The same argv with a `y`, so the refusal above is the operator's and not the flag's.
    let (allowed, asked_again) = asked(argv, BuiltinTool::Write, ApprovalDecision::Allow);
    assert_eq!(allowed, ApprovalDecision::Allow);
    assert_eq!(asked_again, 1);
}

/// The `tool_result` is the only account the model gets, so saying no is not enough.
#[test]
fn a_refusal_tells_the_model_which_flag_would_lift_it() {
    let ApprovalDecision::Deny { reason } = verdict(
        &["sandbx", "agent-run", "--", "go"],
        BuiltinTool::Bash,
        &serde_json::Value::Null,
    ) else {
        panic!("bash was approved with no flag");
    };

    assert!(reason.contains("`--allow-tool bash`"), "got {reason}");
}

#[test]
fn an_approved_tool_is_allowed_not_merely_announced() {
    let decision = verdict(
        &["sandbx", "agent-run", "--allow-tool", "bash", "--", "go"],
        BuiltinTool::Bash,
        &serde_json::Value::Null,
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

/// One settled call as the operator reads it.
fn reported(tool: Option<BuiltinTool>, path: &str, outcome: Outcome<'_>) -> String {
    let input = serde_json::json!({ "path": path });
    report(Settled {
        name: tool.as_ref().map_or("shelll", BuiltinTool::name),
        id: "call_1",
        tool,
        input: &input,
        outcome,
    })
}

#[test]
fn a_call_that_ran_names_the_tool_and_its_subject() {
    assert_eq!(
        reported(Some(BuiltinTool::Write), "/work/out.rs", Outcome::Ran),
        "write /work/out.rs"
    );
}

/// #169's misleading row: `--allow-tool write` outside a writable tree announced a write
/// that never happened, the gate having approved it before the policy refused it.
#[test]
fn a_policy_refusal_is_not_reported_as_a_call_that_ran() {
    let error = ToolError::Denied {
        subject: "/etc/passwd".to_string(),
        reason: "no grant covers it".to_string(),
    };
    let line = reported(
        Some(BuiltinTool::Write),
        "/etc/passwd",
        Outcome::Errored(&error),
    );

    assert_eq!(
        line,
        "write /etc/passwd — refused by the policy: no grant covers it"
    );
    assert_ne!(
        line,
        reported(Some(BuiltinTool::Write), "/etc/passwd", Outcome::Ran),
        "a refused write reads exactly as one that ran"
    );
}

/// Neither of these reaches `approve`, so before #169 they reached the operator not at all.
#[test]
fn the_two_refusals_above_the_gate_are_reported() {
    assert_eq!(
        reported(None, "/work/x", Outcome::Unknown),
        "shelll — no tool answers to that name"
    );
    assert_eq!(
        reported(Some(BuiltinTool::Bash), "/work/x", Outcome::NotOffered),
        "bash /work/x — not offered this turn"
    );
}

/// One refusal is read twice — here and in the `tool_result` — and two gates refuse for
/// causes only one of which a flag lifts, so the line carries the gate's own words rather
/// than a second wording that could advise differently.
#[test]
fn the_operators_line_carries_the_reason_the_model_was_given() {
    let ApprovalDecision::Deny { reason } = verdict(
        &["sandbx", "agent-run", "--", "go"],
        BuiltinTool::Bash,
        &serde_json::Value::Null,
    ) else {
        panic!("bash was approved with no flag");
    };

    let line = reported(
        Some(BuiltinTool::Bash),
        "/work/x",
        Outcome::Denied { reason: &reason },
    );

    assert_eq!(line, format!("bash /work/x — refused: {reason}"));
    assert!(line.contains("`--allow-tool bash`"), "got {line}");
}

#[test]
fn a_bash_call_is_reported_by_its_command() {
    let input = serde_json::json!({ "command": "cargo test" });
    let line = report(Settled {
        name: "bash",
        id: "call_1",
        tool: Some(BuiltinTool::Bash),
        input: &input,
        outcome: Outcome::Ran,
    });

    assert_eq!(line, "bash cargo test");
}

/// Arguments carrying neither key are named by tool alone rather than by a guess.
#[test]
fn a_call_with_no_subject_is_still_reported() {
    let input = serde_json::json!({ "pattern": "fn main" });
    let line = report(Settled {
        name: "grep",
        id: "call_1",
        tool: Some(BuiltinTool::Grep),
        input: &input,
        outcome: Outcome::Ran,
    });

    assert_eq!(line, "grep");
}

/// The attack the strip exists for: a path the model chose carries an escape sequence that
/// clears the line and writes a different one, so the record an operator reads is the
/// model's rather than sandbx's.
#[test]
fn an_escape_sequence_in_a_path_cannot_rewrite_the_line() {
    let hostile = "/work/a\x1b[2K\rsandbx: nothing happened";
    assert!(
        hostile.chars().any(char::is_control),
        "the fixture carries no control character, so this asserts nothing"
    );

    let line = reported(Some(BuiltinTool::Write), hostile, Outcome::Ran);

    assert!(
        !line.chars().any(char::is_control),
        "a control character reached the terminal: {line:?}"
    );
    assert!(
        line.starts_with("write /work/a"),
        "the head was displaced: {line:?}"
    );
}

/// Replaced one-for-one rather than dropped: dropping them turns a hostile string into a
/// plausible path, which is a worse report than a visibly mangled one.
#[test]
fn a_stripped_control_character_leaves_a_mark() {
    assert_eq!(printable("/work/a\nb"), "/work/a\u{fffd}b");
}

#[test]
fn an_argument_too_long_to_read_is_marked_as_cut() {
    let long = "x".repeat(SUBJECT_CAP + 10);

    let cut = printable(&long);
    assert_eq!(cut.chars().count(), SUBJECT_CAP + 1);
    assert!(cut.ends_with('…'), "the cut was silent");

    let whole = "y".repeat(SUBJECT_CAP);
    assert_eq!(printable(&whole), whole, "an argument at the cap was cut");
}
