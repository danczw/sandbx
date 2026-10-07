//! The second turn a round limit earns: no tool may be called, so the reply is prose.
//!
//! Its own module because it changes for a different reason than the rest of `agent-run`:
//! what a turn out of rounds is worth asking next, not what was asked or allowed. See
//! `context/decision-round-limit-answer.md` for why the request is spent at all.

use std::io::Write;

use sandbx_agent::{
    ApprovalDecision, PromptUsage, Turn, TurnLimits, TurnOutcome, TurnStop, run_turn,
};
use sandbx_providers::{EventStream, MessagesRequest, ProviderError, RequestMessage, ToolChoice};
use sandbx_tools::{BuiltinTool, ExecutionContext};

use super::Render;

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

/// What the wrap-up round reuses from the turn that ran out of rounds.
///
/// A struct rather than a borrow because `run_turn` takes its [`Turn`] by value, so these
/// are read off before the first call rather than after it.
pub(super) struct Next {
    model: String,
    max_tokens: u32,
    system: Option<String>,

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
            max_tokens: turn.max_tokens,
            system: Some(match turn.system.as_deref() {
                Some(system) => format!("{system}\n\n{NUDGE}"),
                None => NUDGE.to_owned(),
            }),
            tools: turn.tools.to_vec(),
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
            // Not `gate::decide`: a model that asks for a tool anyway must not reach
            // `sandbx-tools` on the strength of this run's `--allow-tool`.
            |_| ApprovalDecision::Deny {
                reason: REFUSED.to_owned(),
            },
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
            // stands and prose this round already streamed is `Capped::Discarded`.
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
            max_tokens: self.max_tokens,
            system: self.system.clone(),
            tools: &self.tools,
            tool_choice: Some(ToolChoice::None),
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
