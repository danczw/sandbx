use super::{Ending, Unfinished, counted, of};
use sandbx_event::StopReason;
use sandbx_session_message::TurnStop as StoredStop;
use sandbx_turn::{TurnOutcome, TurnStop};

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

/// Every way a finished turn reaches either front end, with the code as a literal: read
/// off the consts, this would only prove the module agrees with itself.
///
/// The `Answered`, `EndTurn` row is the vacuity check: it exits 0 with nothing said, so
/// each non-zero code below is its stop, its cap or its cut, and not the function.
#[test]
fn every_finished_turn_has_one_code_and_its_lines() {
    let capped = TurnStop::RoundLimit { rounds: 4 };
    let whole = || Some(StopReason::EndTurn);
    let cut = || Some(StopReason::MaxTokens);
    let cases = [
        // Neither bound.
        (
            TurnStop::Answered,
            None,
            whole(),
            0,
            0,
            StoredStop::Answered,
        ),
        // `--max-tokens` cut the round with the reply: `Answered` alone would exit 0.
        (TurnStop::Answered, None, cut(), 2, 1, StoredStop::Answered),
        // `--max-rounds`, wrap-up skipped or not attempted.
        (capped, None, None, 2, 1, StoredStop::RoundLimit),
        (
            capped,
            Some(Unfinished::CutShort(4)),
            None,
            2,
            1,
            StoredStop::RoundLimit,
        ),
        // Both bounds, both named.
        (capped, None, cut(), 2, 2, StoredStop::RoundLimit),
        // The wrap-up round answered: prose about cut-off work, not a finished turn (#232).
        (
            TurnStop::Answered,
            Some(Unfinished::Summarised(4)),
            whole(),
            2,
            1,
            StoredStop::Summarised,
        ),
        // A summary cut at `--max-tokens` reads as a whole one unless both are named.
        (
            TurnStop::Answered,
            Some(Unfinished::Summarised(4)),
            cut(),
            2,
            2,
            StoredStop::Summarised,
        ),
        (
            capped,
            Some(Unfinished::Discarded(4)),
            None,
            2,
            1,
            StoredStop::RoundLimit,
        ),
        // A lost operator is not a bound, and only it is unrecoverable (#218).
        (
            TurnStop::GateAborted,
            None,
            None,
            3,
            1,
            StoredStop::GateAborted,
        ),
        // The cut adds its line and does not lower the code.
        (
            TurnStop::GateAborted,
            None,
            cut(),
            3,
            2,
            StoredStop::GateAborted,
        ),
        // Reached by neither front end's finished turn today; stopped is not answered.
        (
            TurnStop::Interrupted,
            None,
            None,
            2,
            1,
            StoredStop::Interrupted,
        ),
    ];

    for (stop, unfinished, round_stop, code, lines, stored) in cases {
        let case = format!("{stop:?}, {unfinished:?}, {round_stop:?}");
        let Ending {
            code: got,
            said,
            stored: kept,
        } = of(&outcome(stop, round_stop), unfinished);

        assert_eq!(got, code, "{case}: {said:?}");
        assert_eq!(said.len(), lines, "{case}: {said:?}");
        assert_eq!(kept, stored, "{case}");
        assert!(
            said.iter().all(|line| line.starts_with("sandbx: ")),
            "{case}: {said:?}"
        );
    }
}

/// Three lines and not one: a summary must not read as a turn that ended on tool work,
/// nor a discarded wrap-up as either. Each names the flag that would have let it go on.
#[test]
fn each_way_out_of_rounds_has_its_own_line() {
    let capped = TurnStop::RoundLimit { rounds: 4 };
    let line = |stop, unfinished| of(&outcome(stop, None), Some(unfinished)).said.remove(0);

    let cut = line(capped, Unfinished::CutShort(4));
    let summarised = line(TurnStop::Answered, Unfinished::Summarised(4));
    let discarded = line(capped, Unfinished::Discarded(4));

    assert!(cut != summarised && summarised != discarded && cut != discarded);
    for said in [&cut, &summarised, &discarded] {
        assert!(said.contains("`--max-rounds`"), "{said}");
    }
    // `--no-wrap-up` reaches `tui` without a `CutShort`, and must read the same.
    assert_eq!(of(&outcome(capped, None), None).said, [cut]);
}

/// The turn's end before the round's cut, and the lost operator first of all: it is the
/// one a caller cannot find out any other way.
#[test]
fn the_turns_end_is_said_before_the_cut() {
    let cut = || Some(StopReason::MaxTokens);

    let Ending { said, .. } = of(&outcome(TurnStop::GateAborted, cut()), None);
    assert!(said[0].contains("could no longer ask"), "{said:?}");
    assert!(said[1].contains("`--max-tokens`"), "{said:?}");

    let capped = outcome(TurnStop::RoundLimit { rounds: 4 }, cut());
    let Ending { said, .. } = of(&capped, Some(Unfinished::CutShort(4)));
    assert!(said[0].contains("`--max-rounds`"), "{said:?}");
    assert!(said[1].contains("`--max-tokens`"), "{said:?}");
}

#[test]
fn one_round_is_not_one_rounds() {
    assert_eq!(counted(1), "1 round");
    assert_eq!(counted(4), "4 rounds");
}
