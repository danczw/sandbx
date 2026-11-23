use super::super::{Device, ending};
use super::Render;
use crate::AgentError;
use sandbx_event::{AgentEvent, StopReason};
use sandbx_screen::Reasoning;
use sandbx_turn::{TurnOutcome, TurnStop};
use std::io;
use std::io::Write;

/// What a turn whose gate was lost says, its last round having stopped `round_stop`.
fn gate_lost(round_stop: Option<StopReason>) -> Vec<String> {
    let outcome = TurnOutcome {
        messages: Vec::new(),
        usage: None,
        withheld: 0,
        stop: TurnStop::GateAborted,
        round_stop,
    };
    ending::of(&outcome, None).said
}

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
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A renderer over two in-memory halves, which is every test here but the broken-pipe
/// ones: the real stderr is the suite's own, and libtest captures only the `print!`
/// macros.
fn captured() -> Render<Vec<u8>, Vec<u8>> {
    Render::with(Vec::new(), Vec::new())
}

/// Everything stdout received, and whether it could all be written.
fn rendered(events: &[AgentEvent]) -> Rendered {
    let mut render = captured();
    for event in events {
        render.event(event);
    }

    let closed = render.finish(&[]);
    Rendered {
        written: String::from_utf8(render.out).expect("utf-8"),
        closed,
    }
}

struct Rendered {
    written: String,
    closed: Result<(), AgentError>,
}

/// Stdout is the answer, so a pipe into `jq` or a file is the whole of it. Both halves
/// asserted, and with reasoning asked for as well as not: without the stderr side, a
/// renderer that dropped the reasoning entirely would pass for one that routed it.
#[test]
fn no_part_of_the_reasoning_reaches_stdout() {
    let events = [
        AgentEvent::Thinking {
            delta: "weighing it up".to_string(),
        },
        AgentEvent::ThinkingBlock {
            text: "weighing it up".to_string(),
            signature: "sig-1".to_string(),
        },
        AgentEvent::RedactedThinking {
            data: "EvgBCkgIBR".to_string(),
        },
        text("the answer"),
        stop(StopReason::EndTurn),
    ];

    for reasoning in [Reasoning::Hidden, Reasoning::Shown] {
        let mut render = captured().showing_thinking(reasoning);
        for event in &events {
            render.event(event);
        }
        let closed = render.finish(&[]);

        assert_eq!(
            String::from_utf8(render.out).expect("utf-8"),
            "the answer\n",
            "{reasoning:?}"
        );
        // The replayable block and the redacted one carry a signature nothing may
        // write, so the delta is the whole of what stderr may hold.
        let reasoned = String::from_utf8(render.err).expect("utf-8");
        assert_eq!(
            reasoned,
            if reasoning == Reasoning::Shown {
                "weighing it up\n"
            } else {
                ""
            },
            "{reasoning:?}"
        );
        closed.expect("clean turn");
    }
}

/// On a terminal both halves share the line, so reasoning left part-written would have
/// the answer appended to it and its own newline arrive after.
#[test]
fn the_answer_does_not_continue_a_reasoning_line() {
    let mut render = captured().showing_thinking(Reasoning::Shown);
    render.event(&AgentEvent::Thinking {
        delta: "weighing it up".to_string(),
    });
    assert!(render.thinking_mid_line, "a delta ending mid-line");

    render.event(&text(""));
    assert!(render.thinking_mid_line, "an empty delta is not the answer");

    render.event(&text("the answer"));
    assert!(!render.thinking_mid_line);

    // The newline and nothing more: written twice it is a blank line between the
    // reasoning and the answer, on a terminal showing both.
    let reasoned = String::from_utf8(render.err).expect("utf-8");
    assert_eq!(reasoned, "weighing it up\n");
}

/// A turn that only reasoned wrote nothing, so the "no answer" report is still owed —
/// reasoning on stderr must not count as having written one.
#[test]
fn reasoning_alone_is_not_an_answer() {
    let Rendered { written, closed } = rendered(&[
        AgentEvent::Thinking {
            delta: "weighing it up".to_string(),
        },
        stop(StopReason::EndTurn),
    ]);

    assert_eq!(written, "");
    closed.expect("clean turn");
}

#[test]
fn a_rounds_stop_does_not_terminate_the_answer() {
    let Rendered { written, closed } = rendered(&[
        text("looking"),
        stop(StopReason::ToolUse),
        text(" — found it"),
        stop(StopReason::EndTurn),
    ]);

    // One trailing newline, not one per round.
    assert_eq!(written, "looking — found it\n");
    closed.expect("clean turn");
}

/// Three whole lines in one order: the reasoning terminated first — no `Stop` here, so
/// `finish` owes the newline — then the lost operator ahead of the bound it outranks.
#[test]
fn what_a_turn_is_told_is_whole_lines_in_order() {
    let mut render = captured().showing_thinking(Reasoning::Shown);
    render.event(&AgentEvent::Thinking {
        delta: "weighing it up".to_string(),
    });

    let said = gate_lost(Some(StopReason::MaxTokens));
    render.finish(&said).expect("a reported turn");

    let told = String::from_utf8(render.err).expect("utf-8");
    let mut lines = told.lines();
    assert_eq!(lines.next(), Some("weighing it up"));
    assert_eq!(lines.next(), Some(said[0].as_str()), "got {told:?}");
    assert_eq!(lines.next(), Some(said[1].as_str()), "got {told:?}");
    assert_eq!(lines.next(), None, "got {told:?}");
}

/// Everything stderr received from `deltas` under `--show-thinking`.
fn reasoned(deltas: &[&str]) -> String {
    let mut render = captured().showing_thinking(Reasoning::Shown);
    for delta in deltas {
        render.event(&AgentEvent::Thinking {
            delta: (*delta).to_string(),
        });
    }
    String::from_utf8(render.err).expect("utf-8")
}

/// Concealing what follows, erasing the line before, reordering a line: each replaced,
/// an escape split across two deltas included (#239).
#[test]
fn a_reasoning_delta_cannot_rewrite_the_lines_around_it() {
    assert_eq!(reasoned(&["hidden\x1b[8m"]), "hidden\u{fffd}[8m");
    assert_eq!(reasoned(&["\x1b", "[30;40m"]), "\u{fffd}[30;40m");
    assert_eq!(reasoned(&["\x1b[A\x1b[2K"]), "\u{fffd}[A\u{fffd}[2K");
    assert_eq!(reasoned(&["\r"]), "\u{fffd}");
    assert_eq!(reasoned(&["a\u{202e}b"]), "a\u{fffd}b");
}

/// `Zl` and `Zp` pass `is_control`; a viewer that breaks on them would show a line that
/// reads as sandbx's own, so they become the newline they stand for.
#[test]
fn a_unicode_line_separator_becomes_a_newline() {
    assert_eq!(reasoned(&["a\u{2028}b\u{2029}c"]), "a\nb\nc");
}

/// Ended by what was written, not by what the model sent: read off the raw delta, a
/// trailing separator would leave the line open and its close write a blank one.
#[test]
fn a_trailing_line_separator_ends_the_reasoning_line() {
    let mut render = captured().showing_thinking(Reasoning::Shown);
    render.event(&AgentEvent::Thinking {
        delta: "done\u{2029}".to_string(),
    });
    assert!(!render.thinking_mid_line);

    render.event(&stop(StopReason::EndTurn));
    assert_eq!(String::from_utf8(render.err).expect("utf-8"), "done\n");
}

/// Not a blanket replacement: prose, its line breaks and its indentation pass whole.
#[test]
fn reasoning_that_renders_is_left_alone() {
    let prose = "weighing it up — naïve 日本語 ✓\n\tthen /work/notes.md\n";
    assert_eq!(reasoned(&[prose]), prose);
}

/// Each line about the answer, after whatever the answer left on a terminal; and not
/// into a redirected stderr, which would carry the escape into the log.
#[test]
fn a_line_about_the_answer_resets_only_where_it_renders() {
    for (err, told) in [
        (Device::Terminal, "\x1b[0msandbx: cut\n"),
        (Device::Redirected, "sandbx: cut\n"),
    ] {
        let mut render = captured().rendering(err);
        render.event(&text("hidden\x1b[8m"));
        render
            .finish(&["sandbx: cut".to_string()])
            .expect("truncated turn");

        assert_eq!(String::from_utf8(render.err).expect("utf-8"), told);
    }
}

/// Everything stdout received across a cap, and the gap that marks it.
fn across_the_cap(before: &[AgentEvent], after: &[AgentEvent]) -> String {
    let mut render = captured();
    for event in before {
        render.event(event);
    }

    render.separate();
    for event in after {
        render.event(event);
    }

    render.finish(&[]).expect("rendered");
    String::from_utf8(render.out).expect("utf-8")
}

#[test]
fn a_summary_sits_one_blank_line_below_the_cut() {
    let mid_line = across_the_cap(&[text("looking")], &[text("found three")]);
    assert_eq!(mid_line, "looking\n\nfound three\n");

    let terminated = across_the_cap(&[text("looking\n")], &[text("found three")]);
    assert_eq!(terminated, "looking\n\nfound three\n");
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
    let Rendered { written, .. } = rendered(&[text("partial answ")]);
    assert_eq!(written, "partial answ\n");
}

#[test]
fn a_terminated_answer_is_not_terminated_twice() {
    let Rendered { written, .. } = rendered(&[text("hi\n"), stop(StopReason::EndTurn)]);
    assert_eq!(written, "hi\n");
}

#[test]
fn an_empty_delta_leaves_the_line_where_it_was() {
    let Rendered { written, .. } = rendered(&[text("hi\n"), text(""), stop(StopReason::EndTurn)]);
    assert_eq!(written, "hi\n");
}

#[test]
fn a_turn_that_wrote_nothing_adds_no_newline() {
    let Rendered { written, .. } = rendered(&[stop(StopReason::EndTurn)]);
    assert_eq!(written, "");
}

#[test]
fn a_turn_nothing_can_read_is_reported_not_swallowed() {
    let mut render = Render::with(ClosedPipe, Vec::new());
    render.event(&text("hi"));
    render.event(&stop(StopReason::EndTurn));

    assert!(matches!(render.finish(&[]), Err(AgentError::Output(_))));
}

/// Both can arrive together, and the write failure keeps the exit: `3` would claim an
/// answer was delivered. The account still lands, ahead of the return — the gate's own
/// went to the device that went away, so this is its last record.
#[test]
fn a_broken_stdout_outranks_the_lost_operator() {
    let mut render = Render::with(ClosedPipe, Vec::new());
    render.event(&text("looking"));

    let said = gate_lost(None);
    assert!(matches!(render.finish(&said), Err(AgentError::Output(_))));

    let told = String::from_utf8(render.err).expect("utf-8");
    assert!(
        told.contains("could no longer ask on this terminal"),
        "the stdout failure took the account of the lost operator with it: {told:?}"
    );
    assert!(told.ends_with('\n'), "got {told:?}");
}
