use super::super::prompt::Notes;
use super::super::render::Unfinished;
use super::{WrapUp, merge, streamed};
use sandbx_event::{AgentEvent, StopReason};
use sandbx_turn::{TurnOutcome, TurnStop};

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

/// Records every line noted, for a test to read back.
#[derive(Default)]
struct Said(Vec<String>);

impl Notes for Said {
    fn note(&mut self, line: &str) {
        self.0.push(line.to_string());
    }
}

/// What the round left decides the ending: an answer summarises, text that was not one is
/// discarded, and a round that showed nothing leaves the turn as the cap cut it.
#[test]
fn the_ending_is_what_the_round_left() {
    let capped = || outcome(TurnStop::RoundLimit { rounds: 3 }, None);
    let finish = |answer, wrote, said| {
        let mut notes = Said::default();
        let (kept, ending) = WrapUp {
            answer,
            wrote,
            said,
        }
        .finish(capped(), 3, &mut notes);
        (kept.stop, ending, notes.0)
    };

    let summarised = finish(Some(outcome(TurnStop::Answered, None)), true, None);
    assert_eq!(
        summarised,
        (TurnStop::Answered, Unfinished::Summarised(3), Vec::new())
    );

    // Neither answered, so `first` stands and the reason is noted.
    let why = || Some("sandbx: the wrap-up round replied with nothing".to_string());
    let (stop, ending, said) = finish(None, true, why());
    assert_eq!((stop, ending), (capped().stop, Unfinished::Discarded(3)));
    assert_eq!(said.len(), 1);
    let (stop, ending, said) = finish(None, false, why());
    assert_eq!((stop, ending), (capped().stop, Unfinished::CutShort(3)));
    assert_eq!(said.len(), 1, "a silent failure still says why");
}

/// An empty delta closes every block, so a silent round must not read as one that wrote.
#[test]
fn only_text_with_something_in_it_is_streamed() {
    let text = |delta: &str| AgentEvent::Text {
        delta: delta.to_string(),
    };
    assert!(streamed(&text("found three")));
    assert!(!streamed(&text("")));
}
