//! The question an operator answers before one tool call runs, and where it is asked.
//!
//! Its own module because the consent channel is neither argv nor the policy: it is a
//! terminal, which `agent-run`'s stdout is not. `context/decision-approval-gate.md` has
//! why once per run is still the default.

use std::fs::File;
use std::io::{BufRead, BufReader, Write};

use sandbx_agent::{ApprovalDecision, ToolCall};
use sandbx_tools::{BuiltinTool, RiskLevel};

use super::gate;

/// The device the question is asked on.
///
/// Not stdin and not stdout: stdout carries the model's answer and is piped, and the
/// prompt arrives on argv, so neither end is free to hold a conversation.
const TTY: &str = "/dev/tty";

/// Reset the graphic rendition, written before each question.
///
/// Not part of the question itself, so the text the strip covers stays free of escapes:
/// this one is sandbx's own, on a real terminal only.
const RESET: &str = "\x1b[0m";

/// The flag that asks per call.
///
/// Named once because the refusal that needs it is written where no clap error is.
pub(crate) const APPROVE_CALL: &str = "--approve call";

/// When the operator is asked whether a call may run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(super) enum Approve {
    /// Once, from argv, before the first request.
    Run,
    /// Once per call that does more than read, on the terminal.
    Call,
}

/// What the model is told when the operator says no.
///
/// Says no flag lifts it, so a model told its tools were approved does not spend a round
/// advising the operator to pass one.
const REFUSED: &str = "the operator refused this call; no flag lifts a refusal, though a \
                       later call may still be approved";

/// What the model is told when the terminal can no longer be asked.
const CLOSED: &str = "the operator's terminal is closed, so no call can be approved";

/// What this run has already been consented to beyond the call it was asked about.
struct Consent {
    /// The tools an `a` answer approved for every later call in the run.
    blanket: Vec<BuiltinTool>,
}

impl Consent {
    fn new() -> Self {
        Self {
            blanket: Vec::new(),
        }
    }

    /// Ask about one call, writing the question to `out` and reading the answer from
    /// `input`.
    ///
    /// The two ends are arguments rather than fields so the whole exchange is drivable;
    /// opening the real device is [`Terminal::open`], which is the uncovered part.
    fn ask(
        &mut self,
        call: ToolCall<'_>,
        input: &mut impl BufRead,
        out: &mut impl Write,
    ) -> ApprovalDecision {
        if self.blanket.contains(&call.tool) {
            return ApprovalDecision::Allow;
        }

        let name = call.tool.name();
        loop {
            // Flushed before the read: a question still in a buffer is an operator
            // staring at nothing, and the deadlock has no timeout to end it.
            let asked = write!(
                out,
                "\nsandbx: {}\nsandbx: this call {}. allow it? [y]es / [n]o / [a]ll `{name}` calls > ",
                gate::describe(call.tool, call.input),
                verb(call.tool),
            )
            .and_then(|()| out.flush());
            if asked.is_err() {
                return deny(CLOSED);
            }

            let mut answer = String::new();
            // A read error is as final as an end of input: either way the question
            // cannot be put again, so nothing it would have approved may run.
            if matches!(input.read_line(&mut answer), Ok(0) | Err(_)) {
                return deny(CLOSED);
            }

            match answer.trim() {
                "y" | "yes" => return ApprovalDecision::Allow,
                "n" | "no" => return deny(REFUSED),
                "a" | "all" => {
                    self.blanket.push(call.tool);
                    return ApprovalDecision::Allow;
                }
                // Asked again rather than read as either answer: a typo is not consent,
                // and reading one as a refusal trains an operator to retype blind.
                _ => {}
            }
        }
    }
}

/// What a tool's [`RiskLevel`] is, in the words the question is phrased in.
fn verb(tool: BuiltinTool) -> &'static str {
    match tool.risk() {
        // Unreachable through the gate, which lets a read-only call run unasked.
        RiskLevel::ReadOnly => "reads",
        RiskLevel::Writes => "writes a file",
        RiskLevel::Executes => "runs a program",
    }
}

fn deny(reason: &str) -> ApprovalDecision {
    ApprovalDecision::Deny {
        reason: reason.to_owned(),
    }
}

/// What can be asked about one call.
///
/// A trait so [`gate::ArgvGate`]'s order — argv first, the terminal only after — is
/// testable without a terminal: a fake records whether it was asked at all.
pub(super) trait Ask {
    /// Whether this call may run, as the operator answered.
    fn ask(&mut self, call: ToolCall<'_>) -> ApprovalDecision;
}

/// The controlling terminal, opened to ask and to be answered.
pub(super) struct Terminal {
    input: BufReader<File>,
    /// The same device duplicated: the question is written where it is answered.
    out: File,
    consent: Consent,
}

impl Terminal {
    /// Open the controlling terminal.
    ///
    /// # Errors
    ///
    /// Fails with `ENXIO` when the process has no controlling terminal — under `setsid`,
    /// or in a job runner. That is what [`APPROVE_CALL`] refuses the run over rather than
    /// serving it the argv answer: an operator who asked to decide per call was not
    /// offered the weaker regime.
    pub(super) fn open() -> std::io::Result<Self> {
        let tty = File::options().read(true).write(true).open(TTY)?;

        Ok(Self {
            input: BufReader::new(tty.try_clone()?),
            out: tty,
            consent: Consent::new(),
        })
    }

    /// Drop whatever was typed before the question is asked.
    ///
    /// Canonical mode queues a finished line until something reads it, so an answer typed
    /// earlier is returned by the next read as the answer to *this* call. The model's own
    /// prose reaches this device too, so a counterfeit question printed in the round's
    /// text can harvest a `y` the operator believes they gave something else — the gate
    /// reads inside `approve`, which fixes *which* call consumes an answer but not which
    /// question earned it.
    ///
    /// Both layers go: `tcflush` clears the kernel queue, and one read can deliver several
    /// lines, so [`BufReader`] may already hold a later one. Either alone leaves the path
    /// open. A flush also drops an answer typed early in good faith, which re-asking
    /// covers.
    fn discard_typeahead(&mut self) {
        let _ =
            nix::sys::termios::tcflush(self.input.get_ref(), nix::sys::termios::FlushArg::TCIFLUSH);

        let buffered = self.input.buffer().len();
        self.input.consume(buffered);
    }
}

impl Ask for Terminal {
    fn ask(&mut self, call: ToolCall<'_>) -> ApprovalDecision {
        self.discard_typeahead();

        // The model's answer streams to this same device and may leave an SGR state behind
        // — concealed, or black on black — so the question is written from a known one. A
        // failed write is not handled here: the question's own write fails too, and denies.
        let _ = self.out.write_all(RESET.as_bytes());

        self.consent.ask(call, &mut self.input, &mut self.out)
    }
}

#[cfg(test)]
mod tests;
