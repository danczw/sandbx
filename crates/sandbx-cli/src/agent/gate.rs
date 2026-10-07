//! Which tools this run approved, what the model is told about the rest, and the one line
//! per call an operator reads.
//!
//! Its own module because it changes for a different reason than the rest of `agent-run`:
//! who may approve a call and when. The report is here and not in `render.rs` because only
//! the gate knows what became of a call.

use sandbx_agent::{ApprovalDecision, CallGate, Outcome, Settled, ToolCall};
use sandbx_tools::{BuiltinTool, RiskLevel, ToolError};

use super::prompt::Ask;

/// The flag that lifts the default refusal.
///
/// Named once because a refusal is read twice — on stderr and in the `tool_result` — and
/// the two accounts must not advise differently.
pub(super) const ALLOW_TOOL: &str = "--allow-tool";

/// How much of a model-chosen argument reaches a terminal.
///
/// High enough that a `bash` command an operator is asked to consent to is not cut in
/// practice: consenting to a truncated command is consenting to something unread.
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

impl<T: Ask> CallGate for ArgvGate<'_, T> {
    fn approve(&mut self, call: ToolCall<'_>) -> ApprovalDecision {
        // Argv is the ceiling, asked first: a prompt that could only ever be refused is
        // fatigue with no decision in it, and it would teach an operator to answer `y`.
        if !approves(self.allowed, call.tool) {
            let name = call.tool.name();
            return ApprovalDecision::Deny {
                reason: format!(
                    "the `{name}` tool is not approved for this run: \
                     it runs only when sandbx is started with `{ALLOW_TOOL} {name}`"
                ),
            };
        }

        // A read-only call is never asked about. #165's twenty-prompt turn is what this
        // and the `a` answer exist to avoid, and a `read` has no answer worth taking.
        if call.tool.risk() == RiskLevel::ReadOnly {
            return ApprovalDecision::Allow;
        }

        match &mut self.terminal {
            Some(terminal) => terminal.ask(call),
            None => ApprovalDecision::Allow,
        }
    }

    fn settled(&mut self, call: Settled<'_>) {
        settled(call);
    }
}

/// Write the operator's line for one call.
///
/// Shared with the wrap-up round's gate, which refuses for a different reason but owes the
/// same account: a call the wrap-up refused reached no operator at all before #169.
pub(super) fn settled(call: Settled<'_>) {
    eprintln!("sandbx: {}", report(call));
}

/// The operator's account of one call, without the `sandbx: ` prefix.
///
/// One function for all five outcomes, so a call that was refused cannot read as one that
/// ran (#169) — and nothing announces a call before this, since a line printed when the
/// call was *requested* would claim a run the policy then refused.
fn report(call: Settled<'_>) -> String {
    let head = match call.tool {
        Some(tool) => describe(tool, call.input),
        None => printable(call.name),
    };

    match call.outcome {
        Outcome::Ran => head,
        Outcome::Unknown => format!("{head} — no tool answers to that name"),
        Outcome::NotOffered => format!("{head} — not offered this turn"),
        // The gate's own reason verbatim, not a second wording of it: two gates refuse
        // here for different causes, and the wrap-up round's is not lifted by any flag.
        Outcome::Denied { reason } => format!("{head} — refused: {reason}"),
        // Exhaustive rather than `to_string()`: the error's own `Display` names its subject,
        // which the head has already printed from the arguments.
        Outcome::Errored(error) => match error {
            ToolError::Denied { reason, .. } => format!("{head} — refused by the policy: {reason}"),
            ToolError::BadInput { detail } => format!("{head} — bad arguments: {detail}"),
            ToolError::Failed { detail, .. } => format!("{head} — failed: {detail}"),
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
    match subject(input) {
        Some(subject) => format!("{} {subject}", tool.name()),
        None => tool.name().to_string(),
    }
}

/// What one call is about, read off the arguments the model sent.
///
/// A closed set of keys: every built-in takes a `path` but `bash`, which takes a `command`.
/// A tool whose arguments carry neither is reported by name alone rather than by guessing.
fn subject(input: &serde_json::Value) -> Option<String> {
    let value = input.get("path").or_else(|| input.get("command"))?;

    Some(printable(&match value.as_str() {
        Some(text) => text.to_string(),
        // Not a string, so the schema will reject it — but the line is printed either way,
        // and naming what was sent beats naming nothing.
        None => value.to_string(),
    }))
}

/// `text` as it may be written to a terminal.
///
/// Model-chosen, so an escape sequence in it would rewrite the surrounding line — which
/// for the consent prompt means rewriting the question being answered. Every `Cc`
/// codepoint (C0, C1 and DEL) becomes U+FFFD rather than being dropped, since a dropped
/// one makes a different string look like a plausible path.
pub(super) fn printable(text: &str) -> String {
    let mut out: String = text
        .chars()
        .take(SUBJECT_CAP)
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect();

    // Marked, not silent: an operator who cannot see the whole argument can still refuse.
    if text.chars().nth(SUBJECT_CAP).is_some() {
        out.push('…');
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
