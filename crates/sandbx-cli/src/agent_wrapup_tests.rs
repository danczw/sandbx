use sandbx_event::StopReason;

use super::*;

fn outcome(stop: TurnStop, round_stop: Option<StopReason>) -> TurnOutcome {
    TurnOutcome {
        messages: Vec::new(),
        usage: None,
        withheld: 0,
        stop,
        round_stop,
    }
}

/// Three cases, three wrong `merge`s: `first.round_stop` fails the first, a constant
/// the second, and `.or(first.round_stop)` — `usage`'s own shape — only the third.
#[test]
fn the_merged_turn_takes_the_wrap_ups_reason() {
    let capped = TurnStop::RoundLimit { rounds: 3 };
    let cut = Some(StopReason::MaxTokens);

    let cut_summary = merge(
        outcome(capped, Some(StopReason::ToolUse)),
        outcome(TurnStop::Answered, cut.clone()),
    );
    assert_eq!(cut_summary.round_stop, cut);
    assert_eq!(cut_summary.stop, TurnStop::Answered);

    let whole_summary = merge(
        outcome(capped, cut.clone()),
        outcome(TurnStop::Answered, Some(StopReason::EndTurn)),
    );
    assert_eq!(whole_summary.round_stop, Some(StopReason::EndTurn));

    // The first turn's bound is not inherited, so a `max_tokens` cut on tool-driving
    // rounds is never reported against the summary that replaced them.
    let unreported = merge(outcome(capped, cut), outcome(TurnStop::Answered, None));
    assert_eq!(unreported.round_stop, None);
}
