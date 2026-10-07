//! Which tools this run approved, what the model is told about the rest, and the one line
//! per call an operator reads.
//!
//! Its own module because it changes for a different reason than the rest of `agent-run`:
//! who may approve a call and when. The report is here and not in `render.rs` because only
//! the gate knows what became of a call.

use sandbx_agent::{ApprovalDecision, CallGate, Outcome, Settled, ToolCall};
use sandbx_tools::{BuiltinTool, RiskLevel, ToolError};

use super::prompt::Operator;

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

/// Whether `--approve call` will put anything to the operator in this run.
///
/// Argv is the ceiling and is checked first, and a read-only call is never asked about, so
/// with no `--allow-tool` the flag asks about nothing at all — and a line announcing that
/// every write will be asked for is false for that run.
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
        let line = line(call);

        match &mut self.terminal {
            // Where the question was asked, not on stderr: an operator who redirected it
            // would answer the next call never having seen what this one did.
            Some(terminal) => terminal.report(&line),
            None => eprintln!("{line}"),
        }
    }
}

/// Write the operator's line for one call, to stderr.
///
/// Shared with the wrap-up round's gate, which refuses for a different reason but owes the
/// same account: a call the wrap-up refused reached no operator at all before #169. That
/// round asks nobody, so it has no terminal to write to either.
pub(super) fn settled(call: Settled<'_>) {
    eprintln!("{}", line(call));
}

/// The operator's whole line for one call, prefixed and stripped.
///
/// Stripped here and not only field by field: this is the one place a report reaches a
/// terminal, so a `Display` impl that starts carrying model text cannot re-open the hole
/// behind a formatter nobody re-audited. `SandboxError`'s already did once.
fn line(call: Settled<'_>) -> String {
    format!("sandbx: {}", stripped(&report(call)))
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
        Outcome::Denied { reason } => format!("{head} — refused: {}", printable(reason)),
        // Exhaustive rather than `to_string()`: the error's own `Display` names its subject,
        // which the head has already printed from the arguments.
        //
        // Every field here is stripped too, and not only the head: `SandboxError`'s own
        // `Display` writes the requested path, and serde's quotes the arguments back, so
        // an escape sequence refused by the policy arrives on this line by the tail.
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
/// field, so `{"command": "curl … | sh", "path": "/work/notes.md"}` deserialises, runs the
/// command, and read by presence order would be named by the decoy path — in the consent
/// question as well as in the report. A tool whose arguments carry no subject at all is
/// named alone rather than by a guess.
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
/// Model-chosen text reaches a terminal here, and an escape sequence in it would rewrite
/// the surrounding line — which for the consent prompt means rewriting the question being
/// answered. A stripped codepoint becomes U+FFFD rather than being dropped: dropped, a
/// hostile string reads as a plausible path, which is a worse account than a mangled one.
///
/// Idempotent, so composing it with itself costs only time.
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

/// Whether `c` renders as nothing, or reorders what follows it.
///
/// `char::is_control` is `Cc` exactly, so the `Cf` codepoints pass it: U+202E and the
/// directional isolates make a path *display* as a different path, which an operator then
/// consents to. Spelled out as ranges because `char` has no predicate for the category.
fn invisible(c: char) -> bool {
    matches!(c,
        '\u{00ad}' | '\u{061c}' | '\u{180e}' | '\u{feff}'
        | '\u{200b}'..='\u{200f}'
        | '\u{202a}'..='\u{202e}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{206f}'
        | '\u{fff9}'..='\u{fffb}'
        | '\u{1d173}'..='\u{1d17a}'
        | '\u{e0000}'..='\u{e007f}')
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
