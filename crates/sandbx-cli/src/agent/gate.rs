//! Which tools this run approved, what the model is told about the rest, and the one line
//! per call an operator reads.
//!
//! The report is here and not in `render.rs` because only the gate knows what became of a
//! call.

use sandbx_agent::{ApprovalDecision, CallGate, Outcome, Settled, ToolCall};
use sandbx_providers::invisible;
use sandbx_tools::{BuiltinTool, RiskLevel, ToolError};

use super::prompt::{Operator, to_stderr};

/// The flag that lifts the default refusal.
///
/// Named once because a refusal is read twice — on stderr and in the `tool_result` — and
/// the two accounts must not advise differently.
pub(super) const ALLOW_TOOL: &str = "--allow-tool";

/// How much of a model-chosen argument reaches a terminal.
///
/// The only bound on this path: `ToolError::Failed` builds its subject from the command
/// with none of its own, and its `detail` carries up to `max_bytes`. Cut here is cut
/// unread, so a `bash` command an operator consents to should not reach it (#169).
const SUBJECT_CAP: usize = 512;

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

/// Whether `--approve call` will put anything to the operator in this run.
///
/// Argv is checked first and a read-only call is never asked about, so with no
/// `--allow-tool` the flag asks about nothing — and announcing otherwise would be false.
pub(super) fn asks_about_anything(allowed: Option<&[BuiltinTool]>) -> bool {
    BuiltinTool::ALL
        .iter()
        .any(|tool| tool.risk() != RiskLevel::ReadOnly && approves(allowed, *tool))
}

/// The gate `agent-run` drives: argv decides, an operator may narrow it, and every call
/// is reported once.
///
/// `terminal` is `Some` under `--approve call` alone. Absent, argv is the whole answer and
/// the run asks nobody, which is what makes it usable from a script.
pub(super) struct ArgvGate<'a, T> {
    allowed: Option<&'a [BuiltinTool]>,
    terminal: Option<T>,
}

impl<'a, T> ArgvGate<'a, T> {
    pub(super) fn new(allowed: Option<&'a [BuiltinTool]>, terminal: Option<T>) -> Self {
        Self { allowed, terminal }
    }
}

impl<T: Operator> CallGate for ArgvGate<'_, T> {
    fn approve(&mut self, call: ToolCall<'_>) -> ApprovalDecision {
        // Argv is the ceiling, asked first: a prompt that could only ever be refused
        // teaches an operator to answer `y`.
        if !approves(self.allowed, call.tool) {
            let name = call.tool.name();
            return ApprovalDecision::Deny {
                reason: format!(
                    "the `{name}` tool is not approved for this run: \
                     it runs only when sandbx is started with `{ALLOW_TOOL} {name}`"
                ),
            };
        }

        // Never asked about: a `read` has no answer worth taking, and asking would be
        // #165's twenty-prompt turn.
        if call.tool.risk() == RiskLevel::ReadOnly {
            return ApprovalDecision::Allow;
        }

        match &mut self.terminal {
            Some(terminal) => terminal.ask(call),
            None => ApprovalDecision::Allow,
        }
    }

    fn settled(&mut self, call: Settled<'_>) {
        let line = line(call);

        match &mut self.terminal {
            // Where the question was asked, not on stderr: an operator who redirected it
            // would answer the next call never having seen what this one did.
            Some(terminal) => terminal.report(&line),
            None => to_stderr(&line),
        }
    }
}

/// Write the operator's line for one call, to stderr.
///
/// Shared with the wrap-up round's gate, which refuses for its own reason and owes the same
/// account. That round asks nobody, so it has no terminal to write to either.
pub(super) fn settled(call: Settled<'_>) {
    to_stderr(&line(call));
}

/// The operator's whole line for one call, prefixed and stripped.
///
/// Stripped at the sink and not only field by field, so a `Display` impl that starts
/// carrying model text cannot re-open the hole — `SandboxError`'s did once. Reached from
/// `tui` too, which draws the line rather than printing it, so a second caller of `report`
/// is not a second place to forget the strip.
pub(super) fn line(call: Settled<'_>) -> String {
    format!("sandbx: {}", stripped(&report(call)))
}

/// The operator's account of one call, without the `sandbx: ` prefix.
///
/// All five outcomes here, so a refused call cannot read as one that ran (#169). Nothing
/// announces a call before this: a line printed when it was *requested* would claim a run
/// the policy then refused.
fn report(call: Settled<'_>) -> String {
    let head = match call.tool {
        Some(tool) => describe(tool, call.input),
        None => printable(call.name),
    };

    match call.outcome {
        // A tail like the other four: nothing prints when a call is requested, so a bare
        // head after a 90-second `bash` reads as the call starting rather than ending.
        Outcome::Ran => format!("{head} — ran"),
        Outcome::Unknown => format!("{head} — no tool answers to that name"),
        Outcome::NotOffered => format!("{head} — not offered this turn"),
        // The gate's own reason verbatim, not a second wording of it: two gates refuse
        // here for different causes, and the wrap-up round's is not lifted by any flag.
        Outcome::Denied { reason } => format!("{head} — refused: {}", printable(reason)),
        // Exhaustive rather than `to_string()`: the error's own `Display` names its subject,
        // which the head has already printed from the arguments.
        Outcome::Errored(error) => match error {
            ToolError::Denied { reason, .. } => {
                format!("{head} — refused by the policy: {}", printable(reason))
            }
            ToolError::BadInput { detail } => {
                format!("{head} — bad arguments: {}", printable(detail))
            }
            ToolError::Failed { detail, .. } => format!("{head} — failed: {}", printable(detail)),
            ToolError::TimedOut { after, .. } => {
                format!("{head} — timed out after {after:?} and was killed")
            }
        },
    }
}

/// One call as both the report and the consent prompt name it.
///
/// Shared so an operator reads a call the same way whether they are being asked about it
/// or told what became of it — and so the control-byte strip cannot be had in one place
/// and missed in the other.
pub(super) fn describe(tool: BuiltinTool, input: &serde_json::Value) -> String {
    match subject(tool, input) {
        Some(subject) => format!("{} {subject}", tool.name()),
        None => tool.name().to_string(),
    }
}

/// What one call is about, read off the arguments the model sent.
///
/// Keyed off the tool, never off which key is present: no input type refuses an unknown
/// field, so `{"command": "curl … | sh", "path": "/work/notes.md"}` runs the command while
/// read by presence order it would be named — and consented to — by the decoy path.
fn subject(tool: BuiltinTool, input: &serde_json::Value) -> Option<String> {
    let key = match tool {
        BuiltinTool::Bash => "command",
        _ => "path",
    };
    let value = input.get(key)?;

    Some(printable(&match value.as_str() {
        Some(text) => text.to_string(),
        // Not a string, so the schema will reject it — but the line is printed either way,
        // and naming what was sent beats naming nothing.
        None => value.to_string(),
    }))
}

/// One model-chosen field as it may be written to a terminal: stripped, and cut to length.
///
/// The cap is per field rather than per line, so one long argument cannot push the words
/// that frame it off the end.
pub(super) fn printable(text: &str) -> String {
    let mut rest = text.chars();
    let head: String = rest.by_ref().take(SUBJECT_CAP).collect();
    let mut out = stripped(&head);

    // Marked, not silent: an operator who cannot see the whole argument can still refuse.
    if rest.next().is_some() {
        out.push('…');
    }

    out
}

/// `text` with everything that could rewrite the line around it replaced.
///
/// An escape sequence in model-chosen text rewrites the surrounding line, which for the
/// consent prompt is the question being answered. Replaced with U+FFFD rather than dropped:
/// dropped, a hostile string reads as a plausible path. Idempotent, so the two layers
/// compose.
fn stripped(text: &str) -> String {
    let mut out = String::with_capacity(text.len());

    for c in text.chars() {
        match c {
            // Spelled, not replaced: a heredoc shown as a row of U+FFFD is a command
            // consented to unread, which `SUBJECT_CAP` exists to avoid.
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() || invisible(c) => out.push('\u{fffd}'),
            c => out.push(c),
        }
    }

    out
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
mod tests;
