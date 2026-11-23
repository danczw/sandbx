use super::{Answer, Ending, Unfinished, counted, of};
use sandbx_session_message::TurnStop as StoredStop;
use sandbx_turn::TurnStop;

/// Every way a finished turn reaches either front end, with the code as a literal: read
/// off the consts, this would only prove the module agrees with itself.
///
/// The `Answered`, `Whole` row is the vacuity check: it exits 0 with nothing said, so each
/// non-zero code below is its stop, its cap or its cut, and not the function.
#[test]
fn every_finished_turn_has_one_code_and_its_lines() {
    let capped = TurnStop::RoundLimit { rounds: 4 };
    let cases = [
        // Neither bound.
        (
            TurnStop::Answered,
            None,
            Answer::Whole,
            0,
            0,
            StoredStop::Answered,
        ),
        // `--max-tokens` cut the round with the reply: `Answered` alone would exit 0.
        (
            TurnStop::Answered,
            None,
            Answer::Truncated,
            2,
            1,
            StoredStop::Answered,
        ),
        // `--max-rounds`, wrap-up skipped or not attempted.
        (capped, None, Answer::Whole, 2, 1, StoredStop::RoundLimit),
        (
            capped,
            Some(Unfinished::CutShort(4)),
            Answer::Whole,
            2,
            1,
            StoredStop::RoundLimit,
        ),
        // Both bounds, both named.
        (
            capped,
            None,
            Answer::Truncated,
            2,
            2,
            StoredStop::RoundLimit,
        ),
        // The wrap-up round answered: prose about cut-off work, not a finished turn (#232).
        (
            TurnStop::Answered,
            Some(Unfinished::Summarised(4)),
            Answer::Whole,
            2,
            1,
            StoredStop::Summarised,
        ),
        // A summary cut at `--max-tokens` reads as a whole one unless both are named.
        (
            TurnStop::Answered,
            Some(Unfinished::Summarised(4)),
            Answer::Truncated,
            2,
            2,
            StoredStop::Summarised,
        ),
        (
            capped,
            Some(Unfinished::Discarded(4)),
            Answer::Whole,
            2,
            1,
            StoredStop::RoundLimit,
        ),
        // A lost operator is not a bound, and only it is unrecoverable (#218).
        (
            TurnStop::GateAborted,
            None,
            Answer::Whole,
            3,
            1,
            StoredStop::GateAborted,
        ),
        // The cut adds its line and does not lower the code.
        (
            TurnStop::GateAborted,
            None,
            Answer::Truncated,
            3,
            2,
            StoredStop::GateAborted,
        ),
        // Reached by neither front end's finished turn today; stopped is not answered.
        (
            TurnStop::Interrupted,
            None,
            Answer::Whole,
            2,
            1,
            StoredStop::Interrupted,
        ),
    ];

    for (stop, unfinished, answer, code, lines, stored) in cases {
        let case = format!("{stop:?}, {unfinished:?}, {answer:?}");
        let Ending {
            code: got,
            said,
            stored: kept,
        } = of(stop, unfinished, answer);

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
/// nor a discarded wrap-up as either.
#[test]
fn each_way_out_of_rounds_has_its_own_line() {
    let capped = TurnStop::RoundLimit { rounds: 4 };
    let line = |stop, unfinished| of(stop, Some(unfinished), Answer::Whole).said.remove(0);

    let cut = line(capped, Unfinished::CutShort(4));
    let summarised = line(TurnStop::Answered, Unfinished::Summarised(4));
    let discarded = line(capped, Unfinished::Discarded(4));

    assert!(cut != summarised && summarised != discarded && cut != discarded);
    // `--no-wrap-up` reaches `tui` without a `CutShort`, and must read the same.
    assert_eq!(of(capped, None, Answer::Whole).said, [cut]);
}

/// The lost operator first: it is the one a caller cannot find out any other way.
#[test]
fn the_lost_operator_is_said_before_the_cut() {
    let Ending { said, .. } = of(TurnStop::GateAborted, None, Answer::Truncated);

    assert!(said[0].contains("could no longer ask"), "{said:?}");
    assert!(said[1].contains("`--max-tokens`"), "{said:?}");
}

#[test]
fn one_round_is_not_one_rounds() {
    assert_eq!(counted(1), "1 round");
    assert_eq!(counted(4), "4 rounds");
}
