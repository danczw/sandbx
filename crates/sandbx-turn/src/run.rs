//! One turn: the round loop, the public types it is driven by, and the compaction
//! threading those types carry.
//!
//! One module on purpose: a new way for a turn to stop is one edit to
//! `TurnStop`, to the loop that chooses it and to the outcome that carries it.

use std::time::Duration;

use sandbx_approval::CallGate;
use sandbx_compact::{Compaction, PromptUsage, over_budget, plan_cut};
use sandbx_event::{AgentEvent, StopReason};
use sandbx_prompt::{Prompt, RequestMessage, Role, Thinking, ToolChoice, ToolDefinition};
use sandbx_provider::{EventStream, ProviderError};
use sandbx_tools::{BuiltinTool, ExecutionContext};

use crate::TurnError;
use crate::accumulate::accumulate;
use crate::tools::{Answers, answer_calls, definition};

/// What to ask the model for. Borrows the history, which [`run_turn`] never appends to.
///
/// No `Default`, for [`Prompt`]'s reason.
#[derive(Clone)]
pub struct Turn<'a> {
    /// The model to ask. A freeform string, as [`Prompt`] takes it.
    pub model: String,
    /// The cap on the model's reply. This crate has no default opinion.
    pub max_output_tokens: u32,
    /// The system prompt, omitted from the request entirely when `None`.
    pub system: Option<String>,
    /// The built-ins to offer. An empty slice offers none, not all of them.
    ///
    /// Not the way to stop a model calling one: a [`history`](Self::history) replaying
    /// `tool_use` needs them defined. Keep them and set [`tool_choice`](Self::tool_choice).
    pub tools: &'a [BuiltinTool],

    /// Whether the model may call one of [`tools`](Self::tools). `None` leaves the choice to
    /// it. Dropped from the request when `tools` is empty, the API refusing a choice over
    /// tools nothing defined.
    ///
    /// Bounds nothing on its own: [`ApprovalDecision`](sandbx_approval::ApprovalDecision)
    /// is still all that stands between a requested call and `sandbx-tools` running it.
    pub tool_choice: Option<ToolChoice>,

    /// Whether to ask for the model's reasoning text, which only a renderer sees.
    ///
    /// Changes nothing about replay: on current models the model reasons either way,
    /// and the blocks this loop carries between rounds are the same ones.
    pub thinking: Option<Thinking>,

    /// The conversation so far, oldest first.
    ///
    /// Carries no reasoning blocks: [`TurnOutcome::messages`] strips them, so a
    /// history built the documented way cannot hold one. See
    /// `context/decision-thinking-replay.md`.
    pub history: &'a [RequestMessage],
    /// The bounds this turn runs within.
    pub limits: TurnLimits,

    /// What the previous turn's request cost: [`TurnOutcome::usage`] threaded back as
    /// `observed = outcome.usage.or(observed)`.
    ///
    /// `None` bounds only the first round, which has to build its request before any
    /// figure for it exists.
    pub observed: Option<PromptUsage>,

    /// How many of `history`'s oldest messages the previous turn left out of its
    /// request. [`TurnOutcome::withheld`], threaded back unchanged.
    ///
    /// A floor, not an instruction: this turn may withhold more, never less — unless the
    /// count no longer names a legal cut point, the one case [`TurnOutcome::withheld`] can
    /// come back smaller. Without it compaction bounds nothing, because
    /// [`observed`](Self::observed) measures the *already compacted* request; see
    /// `context/guide-turn-loop.md`. Exact only because appending to history does not move
    /// its prefix's indices.
    pub withheld: usize,
}

/// What one turn came to, and what the next one has to be told about it.
#[derive(Debug)]
pub struct TurnOutcome {
    /// The turns this call produced, oldest first, to be appended to the caller's history.
    ///
    /// Complete but for reasoning: compaction narrows the *request*, never this, since a
    /// loss in stored history would compound every turn. Reasoning is valid only against
    /// the prefix it was produced against, so it cannot outlive the turn that made it.
    pub messages: Vec<RequestMessage>,

    /// What this turn's last round reported, or `None` if no round reported anything.
    ///
    /// Not pre-merged with what was passed in, so "reported nothing" stays distinct from
    /// "reported what you already knew" — and not enough alone, since
    /// [`withheld`](Self::withheld) must thread back too.
    pub usage: Option<PromptUsage>,

    /// How many of the oldest history messages the last request left out.
    ///
    /// `0` covers three cases a caller cannot tell apart: compaction off, on and under budget
    /// with nothing carried in, or over budget with nothing it could legally withhold.
    pub withheld: usize,

    /// What ended the turn, which [`messages`](Self::messages) cannot show.
    pub stop: TurnStop,

    /// Why the turn's last round ended, or `None` if no round completed.
    ///
    /// The provider's word, reported and not acted on: re-entry keys off the presence of
    /// tool calls. Orthogonal to [`stop`](Self::stop) — a turn that ran out of rounds has
    /// a last round too.
    pub round_stop: Option<StopReason>,
}

/// How a turn came to an end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnStop {
    /// The model stopped asking for tools, so the transcript ends on its reply.
    Answered,

    /// The turn ran out of rounds with a tool result the model never answered.
    ///
    /// The transcript is legal to send again but it is not an answer, and not somewhere a
    /// caller may append a user turn of its own.
    RoundLimit {
        /// The cap that was reached.
        rounds: usize,
    },

    /// The gate ended the turn, having lost whatever it decides with.
    ///
    /// The round it stopped is answered in full, so the transcript is as legal to send again
    /// as [`RoundLimit`](Self::RoundLimit)'s. No payload: the gate's reason is in the last
    /// `tool_result`.
    GateAborted,
}

/// The bounds one turn runs within.
#[derive(Debug, Clone, Copy)]
pub struct TurnLimits {
    /// How many times the model may be asked within one turn.
    ///
    /// A turn re-enters once per batch of tool calls, bounding how far a looping or
    /// injected-into model can drive tool execution; reaching it ends the turn as
    /// [`TurnStop::RoundLimit`] rather than quietly.
    pub max_rounds: usize,

    /// How long one round may spend streaming before the turn is abandoned.
    ///
    /// Bounds one round's *consumption*, which `sandbx-anthropic` leaves to a caller: its own
    /// read timeout resets on every chunk, so a connection kept warm while producing nothing
    /// is not bounded by it. Not a bound on the turn itself: an outer deadline would not help a
    /// tool call either, since `spawn_blocking` cannot be cancelled (#26).
    pub stream_timeout: Duration,

    /// Whether to withhold the oldest history from a request that has outgrown a budget,
    /// and how much to keep.
    ///
    /// Off by default, and the only bound here that is lossy: the others refuse to go on
    /// when hit, where this one quietly sends the model less. `None` means a long enough
    /// conversation eventually dies on the provider's context-length error.
    pub compaction: Option<Compaction>,
}

impl Default for TurnLimits {
    fn default() -> Self {
        Self {
            max_rounds: 8,
            // The pressure point is a long extended-thinking generation.
            stream_timeout: Duration::from_secs(300),
            compaction: None,
        }
    }
}

/// Run one turn, accumulating its event stream into replayable messages.
///
/// The loop itself is `context/guide-turn-loop.md`. All three closures are generics rather
/// than `dyn`, which is not `Send` and would make this future unspawnable; `AsyncFnMut`
/// leaves the future unnamed, so a *generic* wrapper cannot add its own `Send` bound to it.
///
/// Every event reaches `observe` in arrival order before being accumulated, serving both a
/// renderer's increments and the replayable form. Re-entry keys off the *presence* of tool
/// calls, never `StopReason::ToolUse`, which is nullable on the wire.
///
/// Reasoning blocks live for the length of one turn: a round replays the ones before it, which
/// the provider requires inside a tool-use turn, and a deepening cut drops what was already
/// sent. See `context/decision-thinking-replay.md`.
///
/// `gate` is the only thing between the model asking for a tool and `sandbx-tools` executing
/// it: [`CallGate::approve`] decides before each call runs, and an
/// [`ApprovalDecision::Deny`](sandbx_approval::ApprovalDecision::Deny) is recoverable within
/// [`TurnLimits::max_rounds`], unlike an
/// [`ApprovalDecision::Abort`](sandbx_approval::ApprovalDecision::Abort), which ends the turn as
/// [`TurnStop::GateAborted`]. `context/decision-approval-gate.md` has the rest.
///
/// Tools run on `spawn_blocking`, uncancellable: dropping this future still lets the
/// blocking task finish, so a turn abandoned mid-tool applies the `write` anyway, recorded
/// only in the audit trail (#26).
///
/// Needs a tokio runtime with the time driver enabled: the per-round bound is
/// `tokio::time::timeout`, which panics with "there is no timer running" otherwise.
/// `#[tokio::main]` and `enable_all()` cover it, `enable_io()` alone does not; the flavour
/// is free, since `spawn_blocking` needs only `rt`.
pub async fn run_turn<F, O, G>(
    mut open: F,
    turn: Turn<'_>,
    ctx: &ExecutionContext,
    mut observe: O,
    mut gate: G,
) -> Result<TurnOutcome, TurnError>
where
    F: AsyncFnMut(Prompt) -> Result<EventStream, ProviderError>,
    O: FnMut(&AgentEvent),
    G: CallGate,
{
    // Built once: the offered set does not change between rounds.
    let definitions: Vec<ToolDefinition> = turn.tools.iter().copied().map(definition).collect();
    let mut produced: Vec<RequestMessage> = Vec::new();

    // The freshest measurement, the caller's until this turn makes one of its own.
    let mut observed = turn.observed;
    // Not seeded from `observed`.
    let mut usage: Option<PromptUsage> = None;
    // Stays `None` under `max_rounds: 0`, the one cap that opens no stream.
    let mut last_stop: Option<StopReason> = None;
    let mut cut = 0usize;
    // The carried floor until this turn plans its own, so a floor no boundary meets isn't
    // re-asked every round.
    let mut floor = turn.withheld;
    // Not yet acted on by any plan, the caller's absent one included — holds the floor on
    // round one.
    let mut measured = true;
    // What the last request withheld, `None` before there was one.
    let mut sent_cut: Option<usize> = None;

    for _ in 0..turn.limits.max_rounds {
        if measured && let Some(policy) = turn.limits.compaction {
            // Within budget asks only to hold the floor; `None` would undo the cut already
            // paid for.
            let keep_recent =
                over_budget(observed, policy.budget_tokens).then_some(policy.keep_recent);
            // A plan always contains the previous cut, so `unwrap_or` stops a declined plan
            // from restoring history.
            cut = plan_cut(turn.history, produced.len(), keep_recent, floor).unwrap_or(cut);
            floor = cut;
            measured = false;
        }

        // A reasoning block is valid only against the messages before it, so a deepened cut
        // invalidates every one sent; dropping them is the one edit the provider's check permits.
        if sent_cut.is_some_and(|previous| previous != cut) {
            drop_thinking(&mut produced);
        }
        sent_cut = Some(cut);

        let mut messages = turn.history[cut..].to_vec();
        messages.extend_from_slice(&produced);

        let prompt = Prompt {
            model: turn.model.clone(),
            max_output_tokens: turn.max_output_tokens,
            system: turn.system.clone(),
            messages,
            tools: definitions.clone(),
            tool_choice: turn.tool_choice,
            thinking: turn.thinking,
        };

        let mut stream = open(prompt).await.map_err(TurnError::Provider)?;

        // Only the consumption: opening the stream is bounded by the provider's own connect
        // and read timeouts.
        let round = tokio::time::timeout(
            turn.limits.stream_timeout,
            accumulate(&mut stream, &mut observe),
        )
        .await
        .map_err(|_| TurnError::TimedOut {
            after: turn.limits.stream_timeout,
        })??;

        // Before any exit below, since counts matter even on the round that ends the turn.
        if let Some(reported) = round.usage {
            usage = Some(reported);
            observed = Some(reported);
            measured = true;
        }
        last_stop = Some(round.reason);

        // Reasoning doesn't count: stripped on the way out, so a round producing only that
        // leaves an empty content array the API rejects.
        if !round.blocks.iter().any(|block| !block.is_thinking()) {
            // Unless a `tool_result` is waiting to be answered; see `EndedMidToolUse`.
            if matches!(produced.last(), Some(last) if matches!(last.role, Role::User)) {
                return Err(TurnError::EndedMidToolUse);
            }

            return Ok(outcome(produced, usage, cut, TurnStop::Answered, last_stop));
        }

        // Before pushing: answering borrows `round.blocks`, pushing moves them.
        let Answers { results, aborted } =
            answer_calls(&round.blocks, ctx, turn.tools, &mut gate).await?;

        produced.push(RequestMessage {
            role: Role::Assistant,
            content: round.blocks,
        });

        if results.is_empty() {
            // Reads the latch rather than answering outright: no abort leaves a round without
            // a result today, and this is the one place one could be laundered into an answer.
            let stop = if aborted {
                TurnStop::GateAborted
            } else {
                TurnStop::Answered
            };
            return Ok(outcome(produced, usage, cut, stop, last_stop));
        }

        produced.push(RequestMessage {
            role: Role::User,
            content: results,
        });

        // After the push, so the transcript ends on this round's results, as `RoundLimit`
        // already hands back.
        if aborted {
            return Ok(outcome(
                produced,
                usage,
                cut,
                TurnStop::GateAborted,
                last_stop,
            ));
        }
    }

    // Returned rather than dropped: every prefix ends unanswered too, so no truncation reads
    // as finished; `stop` says so.
    Ok(outcome(
        produced,
        usage,
        cut,
        TurnStop::RoundLimit {
            rounds: turn.limits.max_rounds,
        },
        last_stop,
    ))
}

/// The one exit from [`run_turn`], so no path can return reasoning to a caller.
fn outcome(
    mut produced: Vec<RequestMessage>,
    usage: Option<PromptUsage>,
    withheld: usize,
    stop: TurnStop,
    round_stop: Option<StopReason>,
) -> TurnOutcome {
    drop_thinking(&mut produced);
    TurnOutcome {
        messages: produced,
        usage,
        withheld,
        stop,
        round_stop,
    }
}

/// Drop every reasoning block, and any turn left with nothing else in it.
///
/// Both kinds go together, the provider checking for a gap rather than for a type: an
/// emptied turn can only be the last one, since a round producing only reasoning asks for
/// no tools and ends the loop, so removing it cannot leave two user turns adjacent.
fn drop_thinking(messages: &mut Vec<RequestMessage>) {
    for message in messages.iter_mut() {
        message.content.retain(|block| !block.is_thinking());
    }
    messages.retain(|message| !message.content.is_empty());
}
