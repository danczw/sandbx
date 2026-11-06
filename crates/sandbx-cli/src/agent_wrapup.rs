//! The second turn a round limit earns: no tool may be called, so the reply is prose.
//!
//! Its own module because it changes for a different reason than the rest of `agent-run`
//! and `tui`, its two callers: what a turn out of rounds is worth asking next, not what was
//! asked or allowed.
//!
//! The request is spent because the cap otherwise leaves stdout empty in the common case, a
//! model that opened with a tool call: tokens burnt, edits applied, no answer. Hence on by
//! default; `--no-wrap-up` costs the answer and not the conversation, the turn being stored
//! either way (#188, #204, #209).
//!
//! The tools stay offered under `ToolChoice::None` rather than emptied: the history replays
//! the turn's `tool_use` and `tool_result` blocks, which the Messages API refuses without the
//! definitions they name, so an empty list would 400 on every real run. `tool_choice` bounds
//! what is asked for, not what runs; [`RefuseAll`] is the bound.
//!
//! The exit stays 2. A summary is prose about work that was cut off, not a finished turn, so
//! a script sees the same status either way, and the account is what tells the two apart —
//! the split `--max-tokens` truncation uses.

use sandbx_approval::{ApprovalDecision, CallGate, Settled, ToolCall};
use sandbx_event::AgentEvent;
use sandbx_prompt::{Prompt, ToolChoice};
use sandbx_provider::{EventStream, ProviderError};
use sandbx_tools::ExecutionContext;
use sandbx_turn::{Turn, TurnLimits, TurnOutcome, TurnStop, run_turn};

use super::prompt::Notes;
use super::render::Unfinished;

/// What the model is told in place of the tools it may no longer call.
///
/// Appended to the run's own system prompt rather than sent as a user message: the history
/// ends on a `tool_result`, and a second user turn is the consecutive pair the API
/// rejects. A suffix is also never stored, where a text block added to that trailing
/// message would be replayed on every later resume.
const NUDGE: &str = "You have no tool calls left. Answer now from what you have already \
                     found, and say plainly what you could not finish.";

/// Why the gate refuses every call this round, as the model would read it.
///
/// Reached only by a model that ignored both the nudge and `tool_choice`, so the sentence
/// is about the round rather than about a flag: `--allow-tool` would not lift it.
const REFUSED: &str = "no tool may be called while answering a turn that ran out of rounds";

/// The wrap-up round's gate: nothing runs, whatever this run's `--allow-tool` said.
///
/// Not `ArgvGate`, which would let a model that ignored both the nudge and `tool_choice`
/// reach `sandbx-tools` on the strength of a flag meant for the turn before this one. A
/// `Deny` and never an `ApprovalDecision::Abort`: this gate has no channel to lose, so the
/// stop test below can read anything but [`TurnStop::Answered`] as a tool asked for.
///
/// `S` is where the refusal is reported: stderr under `agent-run`, the pane under `tui`.
struct RefuseAll<S>(S);

impl<S: FnMut(Settled<'_>)> CallGate for RefuseAll<S> {
    fn approve(&mut self, _: ToolCall<'_>) -> ApprovalDecision {
        ApprovalDecision::Deny {
            reason: REFUSED.to_owned(),
        }
    }

    fn settled(&mut self, call: Settled<'_>) {
        (self.0)(call);
    }
}

/// Ask once more, over `turn`'s history plus `first`'s messages, and say whether it answered.
///
/// `first` is borrowed, so a caller whose wait is cut short still holds the turn to store.
/// `observe` and `settle` are the caller's sinks, so the round is drawn where the turn was.
pub(super) async fn run(
    open: impl AsyncFnMut(Prompt) -> Result<EventStream, ProviderError>,
    ctx: &ExecutionContext,
    turn: Turn<'_>,
    first: &TurnOutcome,
    mut observe: impl FnMut(&AgentEvent),
    settle: impl FnMut(Settled<'_>),
) -> WrapUp {
    let mut continued = turn.history.to_vec();
    continued.extend(first.messages.iter().cloned());

    // Every field named, so a new one is decided here rather than inherited. The tools stay
    // offered (module doc), so `max_rounds: 1` is all the loop needs.
    let wrap_up = Turn {
        model: turn.model,
        max_output_tokens: turn.max_output_tokens,
        system: Some(match turn.system.as_deref() {
            Some(system) => format!("{system}\n\n{NUDGE}"),
            None => NUDGE.to_owned(),
        }),
        tools: turn.tools,
        tool_choice: Some(ToolChoice::None),
        thinking: turn.thinking,
        history: &continued,
        limits: TurnLimits {
            max_rounds: 1,
            ..turn.limits
        },
        observed: first.usage.or(turn.observed),
        // Still the request's index space, the one `first` counted in: `history` is
        // that request with the turn's messages appended, which moves no prefix.
        withheld: first.withheld,
    };

    let mut wrote = false;
    let second = run_turn(
        open,
        wrap_up,
        ctx,
        |event| {
            wrote |= streamed(event);
            observe(event);
        },
        RefuseAll(settle),
    )
    .await;

    match second {
        // Reported, not propagated: a `?` here would turn a turn that did real work
        // into exit 1 with its text already written.
        Err(error) => WrapUp {
            answer: None,
            wrote,
            said: Some(format!(
                "sandbx: the wrap-up request failed: {}",
                crate::error_line(&error)
            )),
        },
        // Either leaves the batch on an unanswered `tool_result`: `first` stands, and prose
        // already streamed is `Unfinished::Discarded`. Reading every non-answer stop as a tool
        // asked for is sound only while `RefuseAll` cannot abort (its doc).
        Ok(second) if second.messages.is_empty() || second.stop != TurnStop::Answered => WrapUp {
            answer: None,
            wrote,
            said: Some(format!(
                "sandbx: the wrap-up round {}",
                if second.messages.is_empty() {
                    "replied with nothing"
                } else {
                    "asked for a tool instead of answering"
                }
            )),
        },
        Ok(second) => WrapUp {
            answer: Some(second),
            wrote,
            said: None,
        },
    }
}

/// Whether `event` shows the operator any text. An empty delta arrives at every block's
/// close, so counting it would call a silent round [`Unfinished::Discarded`].
fn streamed(event: &AgentEvent) -> bool {
    matches!(event, AgentEvent::Text { delta } if !delta.is_empty())
}

/// What [`run`] came to, before it is joined to the turn it followed.
pub(super) struct WrapUp {
    /// The round, where it answered.
    answer: Option<TurnOutcome>,
    /// Whether the round streamed any text, answer or not.
    wrote: bool,
    /// Why the round is not the answer.
    said: Option<String>,
}

impl WrapUp {
    /// The turn to store, and how a turn that ran out after `rounds` ended. A round that
    /// did not answer leaves `first` exactly as it was (#188), and says why on `notes`.
    ///
    /// A round that failed after streaming prose has already shown text that no
    /// transcript will account for, which `CutShort` would deny.
    pub(super) fn finish(
        self,
        first: TurnOutcome,
        rounds: usize,
        notes: &mut impl Notes,
    ) -> (TurnOutcome, Unfinished) {
        if let Some(line) = &self.said {
            notes.note(line);
        }

        match (self.answer, self.wrote) {
            (Some(second), _) => (merge(first, second), Unfinished::Summarised(rounds)),
            (None, true) => (first, Unfinished::Discarded(rounds)),
            (None, false) => (first, Unfinished::CutShort(rounds)),
        }
    }
}

/// The two turns as the one turn a caller stores.
///
/// `stop` and `round_stop` both come from the wrap-up round, whose prose is the answer.
/// Not `.or`, as `usage` is: a count persists across rounds, a stop reason belongs to one.
pub(super) fn merge(first: TurnOutcome, second: TurnOutcome) -> TurnOutcome {
    let mut messages = first.messages;
    messages.extend(second.messages);

    TurnOutcome {
        messages,
        usage: second.usage.or(first.usage),
        withheld: second.withheld,
        stop: second.stop,
        round_stop: second.round_stop,
    }
}

#[cfg(test)]
#[path = "agent_wrapup_tests.rs"]
mod tests;
