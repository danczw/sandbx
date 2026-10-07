//! The second turn a round limit earns: no tools offered, so the reply is prose.
//!
//! Its own module because it changes for a different reason than the rest of `agent-run`:
//! what a turn out of rounds is worth asking next, not what was asked or allowed. See
//! `context/decision-round-limit-answer.md` for why the request is spent at all.

use std::io::Write;

use sandbx_agent::{PromptUsage, Turn, TurnLimits, TurnOutcome, TurnStop, run_turn};
use sandbx_providers::{EventStream, MessagesRequest, ProviderError, RequestMessage};
use sandbx_tools::{BuiltinTool, ExecutionContext};

use super::{Render, gate};

/// What the model is told in place of the tools it no longer has.
///
/// Appended to the run's own system prompt rather than sent as a user message: the history
/// ends on a `tool_result`, and a second user turn is the consecutive pair the API
/// rejects. A suffix is also never stored, where a text block added to that trailing
/// message would be replayed on every later resume.
const NUDGE: &str = "You have no tool calls left. Answer now from what you have already \
                     found, and say plainly what you could not finish.";

/// What the wrap-up round reuses from the turn that ran out of rounds.
///
/// A struct rather than a borrow because `run_turn` takes its [`Turn`] by value, so these
/// are read off before the first call rather than after it.
pub(super) struct Next {
    model: String,
    max_tokens: u32,
    system: Option<String>,
    limits: TurnLimits,
    observed: Option<PromptUsage>,
}

impl Next {
    /// Carry `turn`'s request over, with the no-tools-left sentence added to its prompt.
    pub(super) fn after(turn: &Turn<'_>) -> Self {
        Self {
            model: turn.model.clone(),
            max_tokens: turn.max_tokens,
            system: Some(match turn.system.as_deref() {
                Some(system) => format!("{system}\n\n{NUDGE}"),
                None => NUDGE.to_owned(),
            }),
            limits: turn.limits,
            observed: turn.observed,
        }
    }

    /// Ask once more, and report whether an answer came back.
    ///
    /// A wrap-up round that fails leaves `first` exactly as it was — unstorable, exit 2,
    /// its text already on stdout — rather than costing it either. That residue is #188.
    pub(super) async fn run<W: Write>(
        &self,
        open: impl AsyncFnMut(MessagesRequest) -> Result<EventStream, ProviderError>,
        ctx: &ExecutionContext,
        allow_tool: Option<&[BuiltinTool]>,
        history: Vec<RequestMessage>,
        first: TurnOutcome,
        render: &mut Render<W>,
    ) -> (TurnOutcome, bool) {
        let mut continued = history;
        continued.extend(first.messages.iter().cloned());

        render.separate();
        let second = run_turn(
            open,
            self.turn(&continued, &first),
            ctx,
            |event| render.event(event),
            // Offered nothing, so it never fires. Passed anyway: `run_turn` has no
            // gate-less form, which is the point of the gate being mandatory.
            |requested| gate::decide(allow_tool, requested),
        )
        .await;

        match second {
            // Reported, not propagated: a `?` here would turn a turn that did real work
            // into exit 1 with its text already written.
            Err(error) => {
                eprintln!("sandbx: the wrap-up request failed: {error}");
                (first, false)
            }
            // No tools were offered, so a `RoundLimit` means a round that asked for one
            // anyway, and no messages means the model declined to answer. Keeping either
            // would leave the batch ending on an unanswered `tool_result` regardless.
            Ok(second) if second.messages.is_empty() || second.stop != TurnStop::Answered => {
                (first, false)
            }
            Ok(second) => (merge(first, second), true),
        }
    }

    /// The turn to ask, over `history` ending in what the first turn produced.
    ///
    /// `tools` is empty, which `Turn::tools` documents as offering none rather than all,
    /// so the model cannot ask for one and `max_rounds: 1` is all the loop needs.
    fn turn<'a>(&self, history: &'a [RequestMessage], first: &TurnOutcome) -> Turn<'a> {
        Turn {
            model: self.model.clone(),
            max_tokens: self.max_tokens,
            system: self.system.clone(),
            tools: &[],
            history,
            limits: TurnLimits {
                max_rounds: 1,
                ..self.limits
            },
            observed: first.usage.or(self.observed),
            // The floor stays exact: `history` is the first turn's history with its
            // messages appended, and appending does not move a prefix's indices.
            withheld: first.withheld,
        }
    }
}

/// The two turns as the one turn a caller stores.
///
/// `stop` comes from the wrap-up round, which is what decides whether the transcript ends
/// on an answer.
pub(super) fn merge(first: TurnOutcome, second: TurnOutcome) -> TurnOutcome {
    let mut messages = first.messages;
    messages.extend(second.messages);

    TurnOutcome {
        messages,
        usage: second.usage.or(first.usage),
        withheld: second.withheld,
        stop: second.stop,
    }
}
