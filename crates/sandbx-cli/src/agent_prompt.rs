//! The question an operator answers before one tool call runs, and where it is asked.
//!
//! Its own module because the consent channel is neither argv nor the policy: it is a
//! terminal, which `agent-run`'s stdout is not. `context/decision-approval-gate.md` has
//! why once per run is still the default.

use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader, ErrorKind, Write};

use sandbx_approval::{ApprovalDecision, ToolCall};
use sandbx_tools::{BuiltinTool, RiskLevel};

use super::{Device, gate};

/// The device the question is asked on.
///
/// Not stdin and not stdout: stdout carries the model's answer and is piped, and the
/// prompt arrives on argv, so neither end is free to hold a conversation.
const TTY: &str = "/dev/tty";

/// Reset the graphic rendition, written before anything sandbx puts on this device.
///
/// The model's answer streams to the same terminal and may leave an SGR state behind —
/// concealed, or black on black — so a question and an account of a call both start from a
/// known one, and a later sink owes the same. Written outside the text the strip covers,
/// this escape being sandbx's own.
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
pub(super) const REFUSED: &str = "the operator refused this call; no flag lifts a refusal, though a \
                       later call may still be approved";

/// What the model is told when the terminal can no longer be asked.
pub(super) const CLOSED: &str = "the operator's terminal is closed, so no call can be approved";

/// What the model is told when the terminal could not be cleared to ask on.
pub(super) const UNCLEARED: &str = "the operator's terminal could not be cleared to ask on, \
                                    so no call can be approved";

/// What the model is told when the operator interrupts at the question.
///
/// A refusal and not a lost channel: the interrupt is the operator speaking, and ends the
/// turn on its own account.
pub(super) const INTERRUPTED: &str =
    "the operator interrupted at this question, so the call was not approved";

/// What this run has already been consented to beyond the call it was asked about.
#[derive(Default)]
pub(super) struct Consent {
    /// The tools an `a` answer approved for every later call in the run.
    blanket: Vec<BuiltinTool>,
}

impl Consent {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Whether an `a` already approved every call to `tool` in this run.
    pub(super) fn covers(&self, tool: BuiltinTool) -> bool {
        self.blanket.contains(&tool)
    }

    /// What one typed answer means for a call to `tool`: `None` for one that is neither
    /// yes, no nor all, which is asked again because a typo is not consent.
    pub(super) fn answer(&mut self, tool: BuiltinTool, typed: &str) -> Option<ApprovalDecision> {
        match typed {
            "y" | "yes" => Some(ApprovalDecision::Allow),
            "n" | "no" => Some(deny(REFUSED)),
            "a" | "all" => {
                self.blanket.push(tool);
                Some(ApprovalDecision::Allow)
            }
            _ => None,
        }
    }

    /// Ask about one call, writing the question to `out` and reading the answer from
    /// `input`.
    ///
    /// The two ends are arguments rather than fields so the exchange is drivable; opening
    /// the real device ([`Terminal::open`]) is the uncovered part.
    fn ask(
        &mut self,
        call: ToolCall<'_>,
        input: &mut impl BufRead,
        out: &mut impl Write,
    ) -> ApprovalDecision {
        if self.covers(call.tool) {
            return ApprovalDecision::Allow;
        }

        let [head, tail] = question(call);
        loop {
            // Flushed before the read: a question still in a buffer is an operator
            // staring at nothing, and the deadlock has no timeout to end it.
            let asked = write!(out, "\n{head}\n{tail} > ").and_then(|()| out.flush());
            if asked.is_err() {
                return abort(CLOSED);
            }

            let mut answer = String::new();
            match input.read_line(&mut answer) {
                // Retried because `read_line`'s UTF-8 check is the only thing that raises
                // `InvalidData` on a `BufReader<File>` — substitute another reader and
                // that has to be re-checked. The line is consumed through its newline, so
                // a rejected answer cannot reach the next read.
                Err(e) if e.kind() == ErrorKind::InvalidData => continue,
                // Every other error is as final as an end of input: a controlling terminal
                // revoked mid-run fails the read with a raw `EIO`, which cannot land in
                // the arm above, where a merely closed one returns 0. One typed `VEOF`
                // goes with them, being indistinguishable from the close.
                Ok(0) | Err(_) => return abort(CLOSED),
                Ok(_) => {}
            }

            // Asked again where there is none: a typo is not consent.
            if let Some(decision) = self.answer(call.tool, answer.trim()) {
                return decision;
            }
        }
    }
}

/// The two lines a call is asked about in, before whatever each surface appends to say
/// where the answer goes.
///
/// One text for both surfaces, so the cap and the strip `describe` carries cover the line
/// prompt and the screen's alike, and an operator is asked the same thing on either.
pub(super) fn question(call: ToolCall<'_>) -> [String; 2] {
    [
        format!("sandbx: {}", gate::describe(call.tool, call.input)),
        format!(
            "sandbx: this call {}. allow it? [y]es / [n]o / [a]ll `{}` calls",
            verb(call.tool),
            call.tool.name()
        ),
    ]
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

pub(super) fn deny(reason: &str) -> ApprovalDecision {
    ApprovalDecision::Deny {
        reason: reason.to_owned(),
    }
}

/// A verdict that ends the turn: the channel is gone, so there is no later call to ask
/// about either.
///
/// Drawn here because this is the only layer that can draw it without guessing — an
/// operator's `n` refuses one call, a read that cannot complete refuses every call there
/// will ever be.
pub(super) fn abort(reason: &str) -> ApprovalDecision {
    ApprovalDecision::Abort {
        reason: reason.to_owned(),
    }
}

/// One account of a call, as the bytes that reach a sink.
///
/// `RESET` only where it renders: `2> run.log` would carry the escape into the log.
/// Formatted whole: `write_fmt`'s syscall per piece leaves the model's own stream a window
/// between the reset and the line it covers.
pub(super) fn account(sink: Device, line: &str) -> String {
    let reset = match sink {
        Device::Terminal => RESET,
        Device::Redirected => "",
    };
    format!("{reset}{line}\n")
}

/// Write one account of a call to stderr.
///
/// A failed write is dropped: this is already the last sink the line has, and raising would
/// cost the turn the exit 3 it still owes its caller (#218).
pub(super) fn to_stderr(line: &str) {
    let mut err = io::stderr();
    let _ = err.write_all(account(Device::of(&err), line).as_bytes());
}

/// Where one line of the run's account goes. One route, so a renderer that owns the screen
/// takes every line rather than have one land on a stderr it covers (#224).
///
/// Not `Account`: CodeQL's `rust/cleartext-logging` reads that name as a credential (#461).
pub(super) trait Notes {
    fn note(&mut self, line: &str);
}

/// The account straight to stderr, for a run with nothing drawn over it.
pub(super) struct Stderr;

impl Notes for Stderr {
    fn note(&mut self, line: &str) {
        to_stderr(line);
    }
}

/// The operator, as the gate reaches them: asked about a call, then told what became of
/// it.
///
/// A trait so that [`gate::ArgvGate`] asking argv first is testable without a terminal: a
/// fake records whether it was asked at all.
pub(super) trait Operator {
    /// Whether this call may run, as the operator answered.
    fn ask(&mut self, call: ToolCall<'_>) -> ApprovalDecision;

    /// Tell the operator what became of one call, where they were asked about it.
    ///
    /// Both directions on one channel or neither: stderr is as redirectable as stdout, so
    /// an operator reading it there would answer call N+1 blind to what call N did.
    fn report(&mut self, line: &str);
}

/// The controlling terminal, opened to ask and to be answered.
///
/// `F` is where an account goes when the terminal refuses it: stderr in a run, and a field
/// rather than a call so a test can read back what reached it (#223).
pub(super) struct Terminal<F = io::Stderr> {
    input: BufReader<File>,
    /// The same device duplicated: the question is written where it is answered.
    out: File,
    consent: Consent,
    fallback: F,
    /// Whether `fallback` renders an SGR escape.
    fallback_device: Device,
}

impl Terminal<io::Stderr> {
    /// Open the controlling terminal.
    ///
    /// # Errors
    ///
    /// Fails with `ENXIO` when the process has no controlling terminal — under `setsid`, or
    /// in a job runner. [`APPROVE_CALL`] refuses the run over it rather than quietly
    /// serving the weaker argv answer.
    pub(super) fn open() -> io::Result<Self> {
        let tty = File::options().read(true).write(true).open(TTY)?;

        Ok(Self {
            input: BufReader::new(tty.try_clone()?),
            out: tty,
            consent: Consent::new(),
            fallback: io::stderr(),
            fallback_device: Device::of(&io::stderr()),
        })
    }

    /// The same terminal over a device already open, for the pty fixture.
    ///
    /// Needed because what the drain clears is the kernel's own input queue, which no
    /// in-memory reader has. [`Terminal::open`] is the only route a run takes.
    #[cfg(test)]
    pub(super) fn on(device: File) -> io::Result<Self> {
        Ok(Self {
            input: BufReader::new(device.try_clone()?),
            out: device,
            consent: Consent::new(),
            fallback: io::stderr(),
            fallback_device: Device::of(&io::stderr()),
        })
    }
}

impl<F> Terminal<F> {
    /// Drop whatever was typed before the question is asked.
    ///
    /// Canonical mode queues a finished line until something reads it, so an answer typed
    /// earlier — at a counterfeit question in the model's own prose, which reaches this
    /// device too — is returned by the next read as the answer to *this* call. Both layers
    /// go: `tcflush` clears the kernel queue, and one read can deliver several lines, so
    /// [`BufReader`] may already hold a later one. Either alone leaves the path open.
    ///
    /// # Errors
    ///
    /// Whatever `tcflush` reports. A flush that failed left the queue intact, so the
    /// caller ends the turn rather than asking over a channel it could not clear.
    fn discard_typeahead(&mut self) -> nix::Result<()> {
        nix::sys::termios::tcflush(self.input.get_ref(), nix::sys::termios::FlushArg::TCIFLUSH)?;

        self.input.consume(self.input.buffer().len());

        Ok(())
    }

    /// The same terminal with its fallback somewhere a test can read back.
    #[cfg(test)]
    pub(super) fn falls_back_to<G>(self, fallback: G, device: Device) -> Terminal<G> {
        Terminal {
            input: self.input,
            out: self.out,
            consent: self.consent,
            fallback,
            fallback_device: device,
        }
    }
}

impl<F: Write> Operator for Terminal<F> {
    fn ask(&mut self, call: ToolCall<'_>) -> ApprovalDecision {
        // Refused rather than retried: EINTR needs a handler installed and this process
        // installs none, so a flush that failed will fail again — and asking anyway is
        // asking over a queue that may already hold its own answer.
        if self.discard_typeahead().is_err() {
            return abort(UNCLEARED);
        }

        // From a known rendition, per `RESET`. A failed write is not handled here: the
        // question's own write fails too, and aborts.
        let _ = self.out.write_all(RESET.as_bytes());

        self.consent.ask(call, &mut self.input, &mut self.out)
    }

    fn report(&mut self, line: &str) {
        // Per `RESET`, the account as much as the question. Unconditional here, where the
        // fallback's is not: this device is a terminal by construction.
        if self
            .out
            .write_all(account(Device::Terminal, line).as_bytes())
            .is_err()
        {
            // Unlike a question, a dropped account reaches nobody — and the last call of a
            // run has no later question whose own failure would stand in for it (#218).
            let text = account(self.fallback_device, line);
            let _ = self.fallback.write_all(text.as_bytes());
        }
    }
}

#[cfg(test)]
#[path = "agent_prompt_tests.rs"]
mod tests;
