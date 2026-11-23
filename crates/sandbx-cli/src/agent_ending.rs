//! What a finished turn exits with, the lines that say why, and how it is stored.
//!
//! One function for both front ends, so `agent-run` and `tui` cannot give one turn two
//! codes. A turn stopped by a key is `tui`'s alone, and layered on top there.

use sandbx_event::StopReason;
use sandbx_session_message::TurnStop as StoredStop;
use sandbx_turn::TurnStop;

use super::prompt::APPROVE_CALL;

/// The exit code for an answer a bound cut short.
///
/// Neither success nor failure: stdout holds the text that arrived before the bound, and
/// nothing at all when the model opened with a tool call. Stderr names the bound.
pub(super) const INCOMPLETE: i32 = 2;

/// The exit code for a run whose operator could no longer be asked.
///
/// Not [`INCOMPLETE`], which means a bound the operator chose cut the turn short, and not
/// a failure: the turn ended on purpose and its work is stored. A caller branching on the
/// status has to be able to tell the three apart (#218).
pub(super) const NO_CONSENT: i32 = 3;

/// Whether the answer was cut off at `--max-tokens`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Answer {
    Whole,
    Truncated,
}

impl Answer {
    /// Read off the stop of the round carrying the reply, whatever ended the turn.
    pub(super) fn of(round_stop: Option<&StopReason>) -> Self {
        if matches!(round_stop, Some(StopReason::MaxTokens)) {
            Self::Truncated
        } else {
            Self::Whole
        }
    }
}

/// How a turn out of rounds ended, which no event reports.
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
}

/// What [`of`] makes of a finished turn.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Ending {
    pub(super) code: i32,
    /// Every line accounting for `code`, in the order they are written. Not `account`:
    /// CodeQL's `rust/cleartext-logging` reads that name as a credential and flags every
    /// assert that prints this list (#461). Rename back once it stops matching.
    pub(super) said: Vec<String>,
    /// How the transcript records the turn's end.
    pub(super) stored: StoredStop,
}

/// The code a finished turn exits with, every line accounting for it, and how it is
/// stored.
///
/// `unfinished` is what became of a turn out of rounds, `None` for any other. A list and
/// not a line, because two bounds can cut one turn: `--max-rounds` ends the turn and
/// `--max-tokens` ends a round inside it. Every cap exits [`INCOMPLETE`], the tool work
/// having been cut off whatever prose followed it.
///
/// Exhaustive on `stop` with no `_` arm, so a new way to end fails to compile here rather
/// than exiting 0.
pub(super) fn of(stop: TurnStop, unfinished: Option<Unfinished>, answer: Answer) -> Ending {
    let mut said = Vec::new();

    let code = match (stop, unfinished) {
        // Ahead of the bounds: one turn can hit `--max-rounds` and lose its operator, and
        // only the second is unrecoverable. A `GateAborted` outcome holds its messages and
        // usage like an answered one, so nothing but the code tells a caller (#218).
        (TurnStop::GateAborted, _) => {
            said.push(format!(
                "sandbx: `{APPROVE_CALL}` could no longer ask on this terminal, so the turn \
                 stopped where it was asked; that call and every call behind it were \
                 refused, nothing after them ran, and no further request was sent"
            ));
            NO_CONSENT
        }
        // Neither front end finishes a turn on this stop: `run_turn` has none of its own,
        // and `tui` accounts for its keys itself. Not 0 should that change.
        (TurnStop::Interrupted, _) => {
            said.push("sandbx: interrupted".to_string());
            INCOMPLETE
        }
        (TurnStop::Answered | TurnStop::RoundLimit { .. }, Some(Unfinished::Summarised(n))) => {
            said.push(format!(
                "sandbx: the answer above summarises what {} of tool calls found; raising \
                 `--max-rounds` would let the turn go further",
                counted(n)
            ));
            INCOMPLETE
        }
        (TurnStop::Answered | TurnStop::RoundLimit { .. }, Some(Unfinished::Discarded(n))) => {
            said.push(format!(
                "sandbx: out of rounds after {}; what the wrap-up round wrote is not an \
                 answer, and is not stored. Raising `--max-rounds` would let the turn go \
                 further",
                counted(n)
            ));
            INCOMPLETE
        }
        (TurnStop::Answered | TurnStop::RoundLimit { .. }, Some(Unfinished::CutShort(n)))
        | (TurnStop::RoundLimit { rounds: n }, None) => {
            said.push(format!(
                "sandbx: out of rounds after {}, so the answer ends on tool work; raising \
                 `--max-rounds` would let the turn go further",
                counted(n)
            ));
            INCOMPLETE
        }
        (TurnStop::Answered, None) => 0,
    };

    // Whatever the stop was: the round carrying the reply can be cut on its own, which is
    // an answer stopping mid-sentence and must not exit 0.
    let code = match answer {
        Answer::Whole => code,
        Answer::Truncated => {
            said.push(
                "sandbx: the answer stops at `--max-tokens`, mid-sentence and not at the \
                 model's own end of turn"
                    .to_string(),
            );
            // Never over a code already chosen, the cut being the recoverable one.
            if code == 0 { INCOMPLETE } else { code }
        }
    };

    Ending {
        code,
        said,
        stored: stored(stop, unfinished),
    }
}

/// How the transcript records a turn's end: `stop`, unless `unfinished` says the answer is
/// the wrap-up round's, which `stop` cannot.
///
/// Exhaustive on both, so a new kind of answer after the cap has to be given a stop here
/// rather than falling through to a whole turn. `Interrupted` cannot say who stopped the
/// turn, so `tui`, which can, does not ask here.
fn stored(stop: TurnStop, unfinished: Option<Unfinished>) -> StoredStop {
    match (stop, unfinished) {
        (TurnStop::Answered, Some(Unfinished::Summarised(_))) => StoredStop::Summarised,
        (TurnStop::Answered, None | Some(Unfinished::CutShort(_) | Unfinished::Discarded(_))) => {
            StoredStop::Answered
        }
        (TurnStop::RoundLimit { .. }, _) => StoredStop::RoundLimit,
        (TurnStop::GateAborted, _) => StoredStop::GateAborted,
        (TurnStop::Interrupted, _) => StoredStop::Interrupted,
    }
}

/// `rounds` with its noun, so a cap of one does not read as "1 rounds".
pub(super) fn counted(rounds: usize) -> String {
    match rounds {
        1 => "1 round".to_string(),
        n => format!("{n} rounds"),
    }
}

#[cfg(test)]
#[path = "agent_ending_tests.rs"]
mod tests;
