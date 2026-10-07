//! Where a turn's output goes: the answer on stdout, everything about it on stderr.
//!
//! Its own module because it changes for a different reason than the rest of `agent-run`:
//! how an answer is presented, not what was asked or allowed. It knows nothing of flags,
//! policies or sessions.

use std::io::Write;

use sandbx_providers::{AgentEvent, StopReason};

use super::INCOMPLETE;
use crate::AgentError;

/// How a turn that ran out of rounds ended, which no event reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Capped {
    /// Nothing reached stdout after the cap, so it holds only what arrived before it.
    CutShort(usize),

    /// A tool-less round answered from what the turn had already found.
    Summarised(usize),

    /// A tool-less round wrote to stdout and then did not answer, so what it wrote is
    /// neither an answer nor stored. Streamed, so it cannot be taken back.
    Discarded(usize),
}

/// Writes a turn out, split so stdout can be piped to something that wants the answer
/// alone.
pub(super) struct Render<W> {
    out: W,

    /// Whether the last round stopped at `max_tokens`. Last-one-wins: every round ends
    /// with a `Stop`, and only the final one says how the turn ended.
    truncated: bool,

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

    /// The first write that failed, kept because `observe` has no way to end the turn.
    failed: Option<std::io::Error>,
}

impl<W: Write> Render<W> {
    pub(super) fn new(out: W) -> Self {
        Self {
            out,
            truncated: false,
            mid_line: false,
            wrote: false,
            separating: false,
            after_gap: false,
            failed: None,
        }
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

    /// Put one event where it belongs.
    pub(super) fn event(&mut self, event: &AgentEvent) {
        match event {
            AgentEvent::Text { delta } => {
                if !delta.is_empty() && std::mem::take(&mut self.separating) {
                    // Two newlines from mid-line, one from a line already terminated.
                    self.write(if self.mid_line { b"\n\n" } else { b"\n" });
                }
                self.write(delta.as_bytes());
                if !delta.is_empty() {
                    self.mid_line = !delta.ends_with('\n');
                    self.after_gap = true;
                }
            }
            AgentEvent::Stop { reason } => {
                self.truncated = matches!(reason, StopReason::MaxTokens);
            }
            // A requested call is announced where it is decided, which knows whether it
            // ran. So a refusal above the gate, or in the wrap-up round, reaches only the
            // model and the turn's own stderr line (#169).
            AgentEvent::ToolCallRequested { .. }
            | AgentEvent::Thinking { .. }
            | AgentEvent::Usage { .. } => {}
        }
    }

    /// Close the answer off, and report what the way it ended means for the exit code.
    ///
    /// `capped` is `Some` when the turn ran out of rounds. Both bounds are named when
    /// both were hit: a summary cut off at `max_tokens` reads as a whole one otherwise,
    /// and which bound ended the turn does not change the code. Every one of them exits
    /// [`INCOMPLETE`] — the tool work was cut off whatever prose followed it.
    pub(super) fn finish(&mut self, capped: Option<Capped>) -> Result<i32, AgentError> {
        if self.mid_line {
            self.write(b"\n");
        }

        if let Some(error) = self.failed.take() {
            return Err(AgentError::Output(error));
        }

        if self.truncated {
            // Otherwise a truncated answer reads as a complete one.
            eprintln!("sandbx: answer truncated at --max-tokens");
        }

        match capped {
            Some(Capped::CutShort(rounds)) => eprintln!(
                "sandbx: stopped after {rounds} rounds of tool calls; \
                 raise --max-rounds to let the turn go further"
            ),
            Some(Capped::Summarised(rounds)) => eprintln!(
                "sandbx: stopped after {rounds} rounds of tool calls; \
                 the answer above summarises what was found, \
                 and raising --max-rounds would let the turn go further"
            ),
            // The text is left where it is rather than disowned quietly: it was paid
            // for, and the operator is the only one who can judge it.
            Some(Capped::Discarded(rounds)) => eprintln!(
                "sandbx: stopped after {rounds} rounds of tool calls; \
                 nothing on stdout is an answer and none of it was saved, \
                 and raising --max-rounds would let the turn go further"
            ),
            None => {}
        }

        if capped.is_some() || self.truncated {
            return Ok(INCOMPLETE);
        }

        Ok(0)
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

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub(crate) fn text(delta: &str) -> AgentEvent {
        AgentEvent::Text {
            delta: delta.to_string(),
        }
    }

    pub(crate) fn stop(reason: StopReason) -> AgentEvent {
        AgentEvent::Stop { reason }
    }

    /// Writes nothing and fails every time, like a pipe whose reader has gone.
    struct ClosedPipe;

    impl Write for ClosedPipe {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Everything stdout received, and what the turn would have exited with.
    fn rendered(events: &[AgentEvent]) -> (String, Result<i32, AgentError>) {
        let mut render = Render::new(Vec::new());
        for event in events {
            render.event(event);
        }

        let code = render.finish(None);
        (String::from_utf8(render.out).expect("utf-8"), code)
    }

    #[test]
    fn a_rounds_stop_does_not_terminate_the_answer() {
        let (written, code) = rendered(&[
            text("looking"),
            stop(StopReason::ToolUse),
            text(" — found it"),
            stop(StopReason::EndTurn),
        ]);

        // One trailing newline, not one per round.
        assert_eq!(written, "looking — found it\n");
        assert_eq!(code.expect("clean turn"), 0);
    }

    #[test]
    fn only_the_last_stop_decides_whether_it_was_cut() {
        let (_, intermediate) = rendered(&[
            stop(StopReason::MaxTokens),
            text("and then it went on"),
            stop(StopReason::EndTurn),
        ]);
        assert_eq!(intermediate.expect("clean turn"), 0);

        let (_, last) = rendered(&[stop(StopReason::EndTurn), stop(StopReason::MaxTokens)]);
        assert_eq!(last.expect("truncated turn"), INCOMPLETE);
    }

    /// The turn's own bound, which no event reports: a round-limited turn ends on a
    /// `ToolUse` stop, the same one a healthy round ends on.
    #[test]
    fn a_turn_out_of_rounds_is_always_incomplete() {
        for capped in [
            Capped::CutShort(3),
            Capped::Summarised(3),
            Capped::Discarded(3),
        ] {
            let mut render = Render::new(Vec::new());
            render.event(&text("looking"));
            render.event(&stop(StopReason::ToolUse));

            // A summary is prose on stdout, not a complete turn: the cap still cut the
            // tool work off, so a script reading the status sees the same thing.
            let code = render.finish(Some(capped)).expect("a reported turn");
            assert_eq!(code, INCOMPLETE, "got {code} for {capped:?}");
        }

        assert_eq!(
            Render::new(Vec::new()).finish(None).expect("clean turn"),
            0,
            "a turn with rounds to spare should still exit 0"
        );
    }

    /// Everything stdout received across a cap, and the gap that marks it.
    fn across_the_cap(before: &[AgentEvent], after: &[AgentEvent]) -> String {
        let mut render = Render::new(Vec::new());
        for event in before {
            render.event(event);
        }

        render.separate();
        for event in after {
            render.event(event);
        }

        render
            .finish(Some(Capped::Summarised(1)))
            .expect("rendered");
        String::from_utf8(render.out).expect("utf-8")
    }

    #[test]
    fn a_summary_sits_one_blank_line_below_the_cut() {
        let mid_line = across_the_cap(&[text("looking")], &[text("found three")]);
        assert_eq!(mid_line, "looking\n\nfound three\n");

        let terminated = across_the_cap(&[text("looking\n")], &[text("found three")]);
        assert_eq!(terminated, "looking\n\nfound three\n");
    }

    #[test]
    fn text_arriving_after_the_gap_is_noticed() {
        let mut render = Render::new(Vec::new());
        render.event(&text("looking"));
        render.separate();
        assert!(!render.wrote_after_gap());

        render.event(&text(""));
        assert!(!render.wrote_after_gap(), "an empty delta is not text");

        render.event(&text("found three"));
        assert!(render.wrote_after_gap());
    }

    /// The gap is owed, not written, so neither end of it can strand a blank line.
    #[test]
    fn a_gap_with_nothing_either_side_is_never_written() {
        assert_eq!(across_the_cap(&[text("looking")], &[]), "looking\n");
        assert_eq!(across_the_cap(&[], &[text("found three")]), "found three\n");
        assert_eq!(across_the_cap(&[], &[]), "");
    }

    #[test]
    fn an_answer_cut_short_mid_line_is_still_terminated() {
        // No `Stop` at all: the shape of a turn that died mid-stream.
        let (written, _) = rendered(&[text("partial answ")]);
        assert_eq!(written, "partial answ\n");
    }

    #[test]
    fn a_terminated_answer_is_not_terminated_twice() {
        let (written, _) = rendered(&[text("hi\n"), stop(StopReason::EndTurn)]);
        assert_eq!(written, "hi\n");
    }

    #[test]
    fn an_empty_delta_leaves_the_line_where_it_was() {
        let (written, _) = rendered(&[text("hi\n"), text(""), stop(StopReason::EndTurn)]);
        assert_eq!(written, "hi\n");
    }

    #[test]
    fn a_turn_that_wrote_nothing_adds_no_newline() {
        let (written, _) = rendered(&[stop(StopReason::EndTurn)]);
        assert_eq!(written, "");
    }

    #[test]
    fn a_turn_nothing_can_read_is_reported_not_swallowed() {
        let mut render = Render::new(ClosedPipe);
        render.event(&text("hi"));
        render.event(&stop(StopReason::EndTurn));

        assert!(matches!(render.finish(None), Err(AgentError::Output(_))));
    }
}
