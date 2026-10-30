use super::super::{Device, INCOMPLETE, NO_CONSENT, gate};
use super::{Tui, ending, lost, reported};
use crate::{AgentError, Cli, Command};
use clap::Parser;
use sandbx_event::StopReason;
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

/// Refused and not downgraded to the argv answer: a flag that asks for a narrower
/// regime must not be served the wider one it asked to replace (#225).
#[test]
fn approve_call_is_refused_whether_or_not_there_is_a_terminal() {
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

    for stdout in [Device::Redirected, Device::Terminal] {
        assert!(
            matches!(tui.drawable(stdout), Err(AgentError::ApproveUnderTui)),
            "{stdout:?}"
        );
    }
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
    let code = |stop| ending(&outcome(stop, None)).0;

    assert_eq!(code(TurnStop::GateAborted), NO_CONSENT);
    assert_eq!(code(TurnStop::RoundLimit { rounds: 4 }), INCOMPLETE);

    // Non-vacuous in the other direction: a finished answer takes the `_` arm and
    // exits 0, so the two codes above are the stops and not the function.
    assert_eq!(ending(&outcome(TurnStop::Answered, None)), (0, Vec::new()));
}

/// The bound `TurnStop` does not carry: a round cut at `--max-tokens` still stops as
/// `Answered`, so reading the stop alone would exit 0 on a truncated reply.
#[test]
fn an_answer_cut_at_max_tokens_exits_two_whatever_the_stop_was() {
    let cut = || Some(StopReason::MaxTokens);

    assert_eq!(ending(&outcome(TurnStop::Answered, cut())).0, INCOMPLETE);
    assert_eq!(
        ending(&outcome(TurnStop::RoundLimit { rounds: 4 }, cut())).0,
        INCOMPLETE
    );

    // The cut does not lower a code already chosen, and it adds its own line to a turn
    // that met both bounds.
    let (code, account) = ending(&outcome(TurnStop::GateAborted, cut()));
    assert_eq!(code, NO_CONSENT);
    assert_eq!(account.len(), 2, "{account:?}");

    // Non-vacuous: the same stop with a round that was not cut exits 0, so the code
    // above is the cut and not the fixture.
    assert_eq!(
        ending(&outcome(TurnStop::Answered, Some(StopReason::EndTurn))).0,
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
        let (code, account) = ending(stop);
        assert_ne!(code, 0, "{stop:?}");
        assert!(
            account.iter().all(|line| line.starts_with("sandbx: ")),
            "{account:?}"
        );
    }
}

/// A finished turn keeps the code it earned, whatever the screen did last.
///
/// Codes as literals, so a const renumbered under a claim `README.md` and `SECURITY.md`
/// both make fails here.
#[test]
fn a_latched_screen_failure_does_not_replace_a_code_the_turn_earned() {
    let latched = || Some(io::Error::from(io::ErrorKind::BrokenPipe));
    let kept = |code| reported(Ok(code), latched(), &[]);

    assert!(matches!(kept(NO_CONSENT), Ok(3)));
    assert!(matches!(kept(INCOMPLETE), Ok(2)));
    assert!(matches!(kept(0), Ok(0)));

    // Non-vacuous: a turn that failed outright reports its own error rather than the
    // screen's, latch or no latch, so what is kept above is the code and not every input.
    let failed = || AgentError::from(TurnError::StreamEndedWithoutStop);
    for screen in [latched(), None] {
        assert!(matches!(
            reported(Err(failed()), screen, &[]),
            Err(AgentError::Turn(TurnError::StreamEndedWithoutStop))
        ));
    }
}

/// A terminal that went away is accounted for as itself, not as an interrupt the
/// operator never made — and it exits 3, the code a lost gate already takes (#264).
///
/// The code as a literal, for the reason the test above it gives.
#[test]
fn a_terminal_that_went_away_is_not_reported_as_an_interrupt() {
    assert!(matches!(reported(Ok(NO_CONSENT), None, &[lost()]), Ok(3)));

    let account = lost();
    assert!(account.starts_with("sandbx: "), "{account}");
    assert!(account.contains("terminal went away"), "{account}");
    assert!(!account.contains("interrupted"), "{account}");
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
