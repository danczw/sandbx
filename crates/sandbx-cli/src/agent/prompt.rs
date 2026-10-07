//! The question an operator answers before one tool call runs, and where it is asked.
//!
//! Its own module because the consent channel is neither argv nor the policy: it is a
//! terminal, which `agent-run`'s stdout is not. `context/decision-approval-gate.md` has
//! why once per run is still the default.

use std::fs::File;
use std::io::{BufRead, BufReader, IsTerminal, Write};

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

/// What the model is told when the terminal could not be cleared to ask on.
const UNCLEARED: &str = "the operator's terminal could not be cleared to ask on, \
                         so no call can be approved";

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

/// Write one account of a call to stderr, from a known graphic rendition.
///
/// The reset only when stderr is a terminal: the model's answer streams to stdout, usually
/// this same device, so a concealing SGR in it would hide every later line — but `2>
/// run.log` would otherwise carry the escape into the log instead.
pub(super) fn to_stderr(line: &str) {
    if std::io::stderr().is_terminal() {
        eprintln!("{RESET}{line}");
    } else {
        eprintln!("{line}");
    }
}

/// The operator, as the gate reaches them: asked about a call, then told what became of
/// it.
///
/// A trait so [`gate::ArgvGate`]'s order — argv first, the terminal only after — is
/// testable without a terminal: a fake records whether it was asked at all.
pub(super) trait Operator {
    /// Whether this call may run, as the operator answered.
    fn ask(&mut self, call: ToolCall<'_>) -> ApprovalDecision;

    /// Tell the operator what became of one call, where they were asked about it.
    ///
    /// Both directions on one channel or neither: stderr is as redirectable as stdout, so
    /// an operator reading the report there would answer the next call without having seen
    /// what this one did.
    fn report(&mut self, line: &str);
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
    ///
    /// # Errors
    ///
    /// Whatever `tcflush` reports. A flush that failed left the queue intact, so the
    /// caller refuses rather than asking over a channel it could not clear.
    fn discard_typeahead(&mut self) -> nix::Result<()> {
        nix::sys::termios::tcflush(self.input.get_ref(), nix::sys::termios::FlushArg::TCIFLUSH)?;

        let buffered = self.input.buffer().len();
        self.input.consume(buffered);

        Ok(())
    }

    /// The same terminal over a device already open, for the pty fixture.
    ///
    /// [`Terminal::open`] is the only route a run takes. This exists because what the
    /// drain clears is the kernel's own input queue, which no in-memory reader has.
    #[cfg(test)]
    fn on(device: File) -> std::io::Result<Self> {
        Ok(Self {
            input: BufReader::new(device.try_clone()?),
            out: device,
            consent: Consent::new(),
        })
    }
}

impl Operator for Terminal {
    fn ask(&mut self, call: ToolCall<'_>) -> ApprovalDecision {
        // Refused rather than retried: EINTR needs a handler installed and this process
        // installs none, so a flush that failed will fail again — and asking anyway is
        // asking over a queue that may already hold its own answer.
        if self.discard_typeahead().is_err() {
            return deny(UNCLEARED);
        }

        // The model's answer streams to this same device and may leave an SGR state behind
        // — concealed, or black on black — so the question is written from a known one. A
        // failed write is not handled here: the question's own write fails too, and denies.
        let _ = self.out.write_all(RESET.as_bytes());

        self.consent.ask(call, &mut self.input, &mut self.out)
    }

    fn report(&mut self, line: &str) {
        // Reset for the same reason the question is: the model's text reached this device
        // too, and a concealing SGR left behind would hide the operator's only account of
        // what ran. One write, so the reset cannot land without the line it covers.
        if writeln!(self.out, "{RESET}{line}").is_err() {
            // The fallback the question has no use for: a refusal reaches the model, but a
            // dropped account reaches nobody, and the last call of a run has no later
            // question whose own failure would stand in for it (#218).
            to_stderr(line);
        }
    }
}

#[cfg(test)]
mod tests;
