//! The second turn a round limit earns: no tool may be called, so the reply is prose.
//!
//! Its own module because it changes for a different reason than the rest of `agent-run`:
//! what a turn out of rounds is worth asking next, not what was asked or allowed. See
//! `context/decision-round-limit-answer.md` for why the request is spent at all.

use std::io::Write;

use sandbx_agent::{
    ApprovalDecision, CallGate, PromptUsage, Settled, ToolCall, Turn, TurnLimits, TurnOutcome,
    TurnStop, run_turn,
};
use sandbx_providers::{EventStream, Prompt, ProviderError, RequestMessage, Thinking, ToolChoice};
use sandbx_tools::{BuiltinTool, ExecutionContext};

use super::{Render, gate};

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
struct RefuseAll;

impl CallGate for RefuseAll {
    fn approve(&mut self, _: ToolCall<'_>) -> ApprovalDecision {
        ApprovalDecision::Deny {
            reason: REFUSED.to_owned(),
        }
    }

    fn settled(&mut self, call: Settled<'_>) {
        gate::settled(call);
    }
}

/// What the wrap-up round reuses from the turn that ran out of rounds.
///
/// A struct rather than a borrow because `run_turn` takes its [`Turn`] by value, so these
/// are read off before the first call rather than after it.
pub(super) struct Next {
    model: String,
    max_output_tokens: u32,
    system: Option<String>,
    thinking: Option<Thinking>,

    /// The same set the first turn offered, owned so the second [`Turn`] can borrow it.
    ///
    /// Still offered though `tool_choice` forbids calling one; see [`Turn::tools`].
    tools: Vec<BuiltinTool>,

    limits: TurnLimits,
    observed: Option<PromptUsage>,
}

impl Next {
    /// Carry `turn`'s request over, with the no-tools-left sentence added to its prompt.
    pub(super) fn after(turn: &Turn<'_>) -> Self {
        Self {
            model: turn.model.clone(),
            max_output_tokens: turn.max_output_tokens,
            system: Some(match turn.system.as_deref() {
                Some(system) => format!("{system}\n\n{NUDGE}"),
                None => NUDGE.to_owned(),
            }),
            thinking: turn.thinking,
            tools: turn.tools.to_vec(),
            limits: turn.limits,
            observed: turn.observed,
        }
    }

    /// Ask once more, and report whether an answer came back.
    ///
    /// A wrap-up round that fails leaves `first` exactly as it was — exit 2, its text
    /// already on stdout, and stored (#188) — rather than costing it any of them. `history`
    /// is borrowed: the caller keeps it to translate the figure this round reports back out
    /// of the request's index space.
    pub(super) async fn run<W: Write, E: Write>(
        &self,
        open: impl AsyncFnMut(Prompt) -> Result<EventStream, ProviderError>,
        ctx: &ExecutionContext,
        history: &[RequestMessage],
        first: TurnOutcome,
        render: &mut Render<W, E>,
    ) -> (TurnOutcome, bool) {
        let mut continued = history.to_vec();
        continued.extend(first.messages.iter().cloned());

        render.separate();
        let second = run_turn(
            open,
            self.turn(&continued, &first),
            ctx,
            |event| render.event(event),
            RefuseAll,
        )
        .await;

        match second {
            // Reported, not propagated: a `?` here would turn a turn that did real work
            // into exit 1 with its text already written.
            Err(error) => {
                eprintln!("sandbx: the wrap-up request failed: {error}");
                (first, false)
            }
            // Either leaves the batch ending on an unanswered `tool_result`, so `first`
            // stands and prose this round already streamed is `Unfinished::Discarded`.
            // The not-equal covers every stop but the answer, which is sound only while
            // `RefuseAll` cannot abort — a gate that could would be misreported here as
            // having asked for a tool.
            Ok(second) if second.messages.is_empty() || second.stop != TurnStop::Answered => {
                eprintln!(
                    "sandbx: the wrap-up round {}",
                    if second.messages.is_empty() {
                        "replied with nothing"
                    } else {
                        "asked for a tool instead of answering"
                    }
                );
                (first, false)
            }
            Ok(second) => (merge(first, second), true),
        }
    }

    /// The turn to ask, over `history` ending in what the first turn produced.
    ///
    /// The tools are offered under [`ToolChoice::None`] rather than withheld as the empty
    /// slice [`Turn::tools`] documents. `max_rounds: 1` is then all the loop needs, a
    /// prose reply ending the turn.
    fn turn<'a>(&'a self, history: &'a [RequestMessage], first: &TurnOutcome) -> Turn<'a> {
        Turn {
            model: self.model.clone(),
            max_output_tokens: self.max_output_tokens,
            system: self.system.clone(),
            tools: &self.tools,
            tool_choice: Some(ToolChoice::None),
            thinking: self.thinking,
            history,
            limits: TurnLimits {
                max_rounds: 1,
                ..self.limits
            },
            observed: first.usage.or(self.observed),
            // Still the request's index space, the one `first` counted in: `history` is
            // that request with the turn's messages appended, which moves no prefix.
            withheld: first.withheld,
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
mod tests {
    use sandbx_providers::StopReason;

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
}
