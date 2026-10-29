//! Where a turn's output goes: the answer on stdout, everything about it on stderr.
//!
//! Its own module because it changes for a different reason than the rest of `agent-run`:
//! how an answer is presented, not what was asked or allowed. It knows nothing of flags,
//! policies or sessions.

use std::io::Write;
use std::{io, mem};

use sandbx_event::AgentEvent;
use sandbx_text::invisible;

use super::prompt::{APPROVE_CALL, account};
use super::{INCOMPLETE, NO_CONSENT};
use crate::AgentError;

/// How a turn ended short of a finished answer, which no event reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Unfinished {
    /// Nothing reached stdout after the cap, so it holds only what arrived before it.
    CutShort(usize),

    /// A tool-less round answered from what the turn had already found.
    Summarised(usize),

    /// A tool-less round wrote to stdout and then did not answer, so what *it* wrote is
    /// neither an answer nor stored, unlike the turn before it. Streamed, so it cannot be
    /// taken back.
    Discarded(usize),

    /// The gate lost the channel it decides on, so the turn ended where it was asked.
    Aborted,
}

/// Writes a turn out, split so stdout can be piped to something that wants the answer
/// alone.
///
/// `E` is the other half — reasoning, and the lines that say how the turn ended. A field
/// rather than a macro so a test can read back what was written and in what order (#223).
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

    /// Whether any text has arrived since the last [`Render::separate`], so a caller can
    /// tell a round that wrote and then failed from one that wrote nothing.
    after_gap: bool,

    /// Whether reasoning was asked for. Off unless
    /// [`crate::agent::AgentRun::show_thinking`] set it, so a summary streamed unasked is
    /// dropped here rather than put in front of an operator who did not want it.
    show_thinking: bool,

    /// Whether stderr is part-way through a line of reasoning, so the round's own stderr
    /// lines do not continue one.
    thinking_mid_line: bool,

    /// Whether stderr renders an SGR escape.
    renders: bool,

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
            after_gap: false,
            show_thinking: false,
            thinking_mid_line: false,
            renders: false,
            failed: None,
        }
    }

    /// Reset the rendition before each line about the answer, `err` being a terminal.
    #[must_use]
    pub(super) fn rendering(mut self, renders: bool) -> Self {
        self.renders = renders;
        self
    }

    /// Let the model's reasoning through to stderr.
    #[must_use]
    pub(super) fn showing_thinking(mut self, show: bool) -> Self {
        self.show_thinking = show;
        self
    }

    /// Ask for a blank line before whatever is written next.
    ///
    /// Owed, not written: the wrap-up round it separates may answer with nothing at all.
    pub(super) fn separate(&mut self) {
        self.separating = self.wrote;
        self.after_gap = false;
    }

    /// Whether anything has reached stdout since [`Render::separate`].
    pub(super) fn wrote_after_gap(&self) -> bool {
        self.after_gap
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
    /// same device.
    fn note(&mut self, line: &str) {
        self.put(account(self.renders, line).as_bytes());
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
                    self.after_gap = true;
                }
            }
            // Stderr, stdout being the answer. Gated rather than trusted to be empty: the
            // API sends the increment whether or not a summary was asked for.
            AgentEvent::Thinking { delta } => {
                // Stripped, being model-chosen: a delta could otherwise hide or erase the
                // lines after it, the gate's verdicts among them (#239).
                if self.show_thinking && !delta.is_empty() {
                    self.put(inert(delta).as_bytes());
                    self.thinking_mid_line = !delta.ends_with('\n');
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

    /// Close the answer off, and report what the way it ended means for the exit code.
    ///
    /// `ending` is `Some` for a turn that ran out of rounds or lost its operator;
    /// `truncated` is passed in rather than inferred here, so a caller with no renderer
    /// sees the same figure. Both bounds are named when both were hit: a summary cut off
    /// at `max_tokens` reads as a whole one otherwise, and which *bound* ended the turn
    /// does not change the code — the three cap variants all exit [`INCOMPLETE`], the
    /// tool work having been cut off whatever prose followed it. A lost operator is not a
    /// bound and exits [`NO_CONSENT`].
    pub(super) fn finish(
        &mut self,
        ending: Option<Unfinished>,
        truncated: bool,
    ) -> Result<i32, AgentError> {
        // Again here, for the round that never reached a `Stop` — a stream error or the
        // per-round timeout — whose report is the next thing on stderr.
        self.end_thinking_line();

        if self.mid_line {
            self.write(b"\n");
        }

        // Before the stdout failure below rather than in the match with the others: the
        // gate's own account of the call went to the device that went away, so an early
        // return for a broken pipe would take the last record of it too.
        if ending == Some(Unfinished::Aborted) {
            self.note(&format!(
                "sandbx: `{APPROVE_CALL}` could no longer ask on this terminal, \
                 so the turn stopped where it was asked; that call and every call \
                 behind it were refused, nothing after them ran, and no further \
                 request was sent"
            ));
        }

        if let Some(error) = self.failed.take() {
            return Err(AgentError::Output(error));
        }

        if truncated {
            // Otherwise a truncated answer reads as a complete one.
            self.note("sandbx: answer truncated at --max-tokens");
        }

        match ending {
            Some(Unfinished::CutShort(rounds)) => self.note(&format!(
                "sandbx: stopped after {rounds} rounds of tool calls; \
                 raise --max-rounds to let the turn go further"
            )),
            Some(Unfinished::Summarised(rounds)) => self.note(&format!(
                "sandbx: stopped after {rounds} rounds of tool calls; \
                 the answer above summarises what was found, \
                 and raising --max-rounds would let the turn go further"
            )),
            // The text is left where it is rather than disowned quietly: it was paid
            // for, and the operator is the only one who can judge it.
            Some(Unfinished::Discarded(rounds)) => self.note(&format!(
                "sandbx: stopped after {rounds} rounds of tool calls; \
                 nothing on stdout is an answer, and what followed the cap was \
                 not saved either — raising --max-rounds would let the turn go further"
            )),
            // Written above, ahead of the stdout failure check.
            Some(Unfinished::Aborted) | None => {}
        }

        // Ahead of `INCOMPLETE`: a turn can hit a bound and lose its operator, and losing
        // the operator is the one a caller cannot find out any other way.
        Ok(if ending == Some(Unfinished::Aborted) {
            NO_CONSENT
        } else if ending.is_some() || truncated {
            INCOMPLETE
        } else {
            0
        })
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

/// `delta` with everything that could rewrite the lines around it replaced with U+FFFD.
///
/// Per character, so it holds across a delta boundary; see
/// `context/decision-thinking-replay.md`.
fn inert(delta: &str) -> String {
    delta
        .chars()
        .map(|c| match c {
            '\n' | '\t' => c,
            c if c.is_control() || invisible(c) => '\u{fffd}',
            c => c,
        })
        .collect()
}

#[cfg(test)]
#[path = "agent_render_tests.rs"]
pub(super) mod tests;
