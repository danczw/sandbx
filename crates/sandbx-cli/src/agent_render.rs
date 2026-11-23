//! Where a turn's output goes: the answer on stdout, everything about it on stderr.
//!
//! Its own module because it changes for a different reason than the rest of `agent-run`:
//! how an answer is presented, not what was asked or allowed. It knows nothing of flags,
//! policies or sessions.

use std::io::Write;
use std::{io, mem};

use sandbx_event::AgentEvent;
use sandbx_screen::Reasoning;
use sandbx_text::{invisible, line_separator};

use super::Device;
use super::prompt::{Notes, account};
use crate::AgentError;

/// Writes a turn out, split so stdout can be piped to something that wants the answer
/// alone.
///
/// `E` is the other half — reasoning, and the lines that say how the turn ended. A field
/// rather than a macro so a test can read back what was written and in what order.
pub(super) struct Render<W, E> {
    out: W,
    err: E,

    /// Whether stdout is part-way through a line, so it is terminated once and only if
    /// the model did not terminate it already.
    mid_line: bool,

    /// Whether anything has reached stdout, so a gap is never the first thing on it.
    wrote: bool,

    /// Whether a gap is owed before the next text — deferred, so a wrap-up round that
    /// answers with nothing leaves no stray blank line.
    separating: bool,

    /// Whether reasoning was asked for. Off unless
    /// [`crate::agent::AgentRun::show_thinking`] set it, so a summary streamed unasked is
    /// dropped here rather than put in front of an operator who did not want it.
    reasoning: Reasoning,

    /// Whether stderr is part-way through a line of reasoning, so the round's own stderr
    /// lines do not continue one.
    thinking_mid_line: bool,

    /// Whether stderr renders an SGR escape.
    err_device: Device,

    /// The first write that failed, kept because `observe` has no way to end the turn.
    failed: Option<io::Error>,
}

impl<W: Write, E: Write> Render<W, E> {
    pub(super) fn with(out: W, err: E) -> Self {
        Self {
            out,
            err,
            mid_line: false,
            wrote: false,
            separating: false,
            reasoning: Reasoning::Hidden,
            thinking_mid_line: false,
            err_device: Device::Redirected,
            failed: None,
        }
    }

    /// Reset the rendition before each line about the answer, `err` being a terminal.
    #[must_use]
    pub(super) fn rendering(mut self, err: Device) -> Self {
        self.err_device = err;
        self
    }

    /// Let the model's reasoning through to stderr.
    #[must_use]
    pub(super) fn showing_thinking(mut self, reasoning: Reasoning) -> Self {
        self.reasoning = reasoning;
        self
    }

    /// Ask for a blank line before whatever is written next.
    ///
    /// Owed, not written: the wrap-up round it separates may answer with nothing at all.
    pub(super) fn separate(&mut self) {
        self.separating = self.wrote;
    }

    /// Terminate a part-written line of reasoning, so nothing continues it.
    fn end_thinking_line(&mut self) {
        if mem::take(&mut self.thinking_mid_line) {
            self.put(b"\n");
        }
    }

    /// Write to the half that is not the answer.
    ///
    /// A failure is dropped: this is the half a stdout failure is reported on, so a second
    /// error here would have no sink left to name it.
    fn put(&mut self, bytes: &[u8]) {
        let _ = self.err.write_all(bytes);
    }

    /// Write one whole line about the answer, from a known rendition per `prompt::RESET`.
    ///
    /// Written once, so a line cannot interleave with the reasoning deltas reaching the
    /// same device. The reset is there because stdout is not stripped — the answer is what a
    /// pipe asked for — so it can leave an SGR state behind; it restores the rendition, not
    /// lines the answer already erased.
    fn note(&mut self, line: &str) {
        self.put(account(self.err_device, line).as_bytes());
    }

    /// Put one event where it belongs.
    pub(super) fn event(&mut self, event: &AgentEvent) {
        match event {
            AgentEvent::Text { delta } => {
                // Before the answer, not just at the round's `Stop`: on a terminal both
                // streams share the line, so reasoning left part-written would have the
                // answer's first line appended to it and its newline arrive after.
                if !delta.is_empty() {
                    self.end_thinking_line();
                }
                if !delta.is_empty() && mem::take(&mut self.separating) {
                    // Two newlines from mid-line, one from a line already terminated.
                    self.write(if self.mid_line { b"\n\n" } else { b"\n" });
                }
                self.write(delta.as_bytes());
                if !delta.is_empty() {
                    self.mid_line = !delta.ends_with('\n');
                }
            }
            // Stderr, stdout being the answer. Gated rather than trusted to be empty: the
            // API sends the increment whether or not a summary was asked for.
            AgentEvent::Thinking { delta } => {
                // Stripped, being model-chosen: a delta could otherwise hide or erase the
                // lines after it, the gate's verdicts among them (#239).
                if self.reasoning == Reasoning::Shown && !delta.is_empty() {
                    let shown = inert(delta);
                    self.put(shown.as_bytes());
                    self.thinking_mid_line = !shown.ends_with('\n');
                }
            }
            AgentEvent::Stop { .. } => {
                // Here and not at the block's close, which an unsigned block never
                // reaches: a round's own stderr lines follow, and none may continue a
                // reasoning line.
                self.end_thinking_line();
            }
            // A call is reported once it has settled, by the gate, which is the only thing
            // that knows what became of it.
            //
            // The two reasoning blocks are the replayable form of what the deltas above
            // already showed, and carry a signature nothing here may write.
            AgentEvent::ToolCallRequested { .. }
            | AgentEvent::ThinkingBlock { .. }
            | AgentEvent::RedactedThinking { .. }
            | AgentEvent::Usage { .. } => {}
        }
    }

    /// Close the answer off, and write `said`, the lines accounting for how it ended.
    ///
    /// Every line ahead of the stdout failure: the gate's own account of a call went to
    /// the device that went away, so an early return for a broken pipe would take the
    /// last record of it too.
    pub(super) fn finish(&mut self, said: &[String]) -> Result<(), AgentError> {
        // Again here, for the round that never reached a `Stop` — a stream error or the
        // per-round timeout — whose report is the next thing on stderr.
        self.end_thinking_line();

        if self.mid_line {
            self.write(b"\n");
        }

        for line in said {
            self.note(line);
        }

        match self.failed.take() {
            Some(error) => Err(AgentError::Output(error)),
            None => Ok(()),
        }
    }

    /// Flushed per call: a line-buffered stdout holds the answer back until the model
    /// happens to emit a newline, which is the difference between streaming and not.
    fn write(&mut self, bytes: &[u8]) {
        if self.failed.is_some() {
            return;
        }

        if let Err(error) = self.out.write_all(bytes).and_then(|()| self.out.flush()) {
            self.failed = Some(error);
        } else {
            self.wrote |= !bytes.is_empty();
        }
    }
}

impl<W: Write, E: Write> Notes for Render<W, E> {
    fn note(&mut self, line: &str) {
        Self::note(self, line);
    }
}

/// `delta` with everything that could rewrite the lines around it replaced with U+FFFD.
///
/// Reasoning is model-chosen, and under `--show-thinking` it shares the terminal with the
/// gate's verdicts: `\x1b[8m` would conceal every one, `\x1b[A\x1b[2K` erase the one before
/// it (#239). Replaced rather than dropped, for the gate's reason. `\n` and `\t` survive,
/// reasoning being prose over many lines, and U+2028 and U+2029 become the `\n` they
/// stand for; uncapped, nothing being consented to on it.
///
/// Per character, not per line, so streaming survives it: a delta is a `&str`, so an escape
/// split across two deltas has its ESC whole in one of them, and what follows is inert text.
/// Buffering to a newline would cost the stream for nothing. What it leaves: a stripped delta
/// keeps its newlines, so it can still print a line that reads as sandbx's own.
fn inert(delta: &str) -> String {
    delta
        .chars()
        .map(|c| match c {
            '\n' | '\t' => c,
            c if line_separator(c) => '\n',
            c if c.is_control() || invisible(c) => '\u{fffd}',
            c => c,
        })
        .collect()
}

#[cfg(test)]
#[path = "agent_render_tests.rs"]
pub(super) mod tests;
