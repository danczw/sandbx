//! One turn: the round loop, the public types it is driven by, and the compaction
//! threading those types carry.
//!
//! Rebuilding a round's message is `accumulate`; running what it asked for is `tools`.

use sandbx_providers::{
    AgentEvent, EventStream, Prompt, ProviderError, RequestMessage, Role, Thinking, ToolChoice,
    ToolDefinition,
};
use sandbx_tools::{BuiltinTool, ExecutionContext};

use crate::{ApprovalDecision, Compaction, ToolCall, TurnError, compact};

mod accumulate;
mod tools;

use accumulate::accumulate;
use tools::{answer_calls, definition};

/// What to ask the model for. Borrows the history, which [`run_turn`] never appends to.
pub struct Turn<'a> {
    /// The model to ask. A freeform string, as [`Prompt`] takes it.
    pub model: String,
    /// The cap on the model's reply. This crate has no default opinion.
    pub max_output_tokens: u32,
    /// The system prompt, omitted from the request entirely when `None`.
    pub system: Option<String>,
    /// The built-ins to offer. An empty slice offers none, not all of them.
    ///
    /// Not the way to stop a model calling one: a [`history`] replaying `tool_use` needs
    /// them defined. Keep them and set [`tool_choice`].
    ///
    /// [`history`]: Self::history
    /// [`tool_choice`]: Self::tool_choice
    pub tools: &'a [BuiltinTool],

    /// Whether the model may call one of [`tools`]. `None` leaves the choice to it.
    ///
    /// Dropped from the request when `tools` is empty, the API refusing a choice over
    /// tools nothing defined. Bounds nothing on its own either way —
    /// [`ApprovalDecision`] is still all that stands between a requested call and
    /// `sandbx-tools` running it.
    ///
    /// [`tools`]: Self::tools
    /// [`ApprovalDecision`]: crate::ApprovalDecision
    pub tool_choice: Option<ToolChoice>,

    /// Whether to ask for the model's reasoning text, which only a renderer sees.
    ///
    /// Changes nothing about replay: on current models the model reasons either way,
    /// and the blocks this loop carries between rounds are the same ones. All this
    /// sets is whether `observe` receives any [`AgentEvent::Thinking`] text to show.
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
    /// come back smaller. Without it compaction bounds nothing, because [`observed`]
    /// measures the *already compacted* request; see `context/guide-turn-loop.md`. Exact
    /// only because appending to history does not move its prefix's indices.
    ///
    /// [`observed`]: Self::observed
    pub withheld: usize,
}

/// The prompt-side token counters of the last `AgentEvent::Usage` a turn reported.
///
/// `None` means "not reported", distinguishable from a reported zero. `output_tokens` is
/// absent: compaction asks how large the *request* was, and `observe` sees the whole
/// event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PromptUsage {
    /// Tokens in the request, excluding anything served from cache.
    pub input_tokens: Option<u32>,
    /// Tokens read from the prompt cache.
    pub cache_read_tokens: Option<u32>,
    /// Tokens written to the prompt cache.
    pub cache_write_tokens: Option<u32>,
}

impl PromptUsage {
    /// The whole prompt, as the provider counted it.
    ///
    /// All three counters summed: a cache read is a real prompt token charged against the
    /// context window. `u64` because three saturated counters overflow a `u32`. An
    /// unreported counter sums as zero — the API omits the cache fields when no cache was
    /// involved, and reading that as "unknown" would disable compaction for every
    /// uncached request.
    #[must_use]
    pub fn prompt_tokens(&self) -> u64 {
        u64::from(self.input_tokens.unwrap_or(0))
            + u64::from(self.cache_read_tokens.unwrap_or(0))
            + u64::from(self.cache_write_tokens.unwrap_or(0))
    }
}

/// What one turn came to, and what the next one has to be told about it.
#[derive(Debug)]
pub struct TurnOutcome {
    /// The turns this call produced, oldest first, to be appended to the caller's history.
    ///
    /// Complete but for reasoning: compaction narrows the *request*, never this, since a
    /// loss in a caller's stored history would compound every turn. Reasoning blocks are
    /// the one exception — they are valid only against the prefix they were produced
    /// against, so carrying them past the turn that made them is what a provider rejects.
    /// A turn left holding nothing but reasoning drops out entirely rather than becoming
    /// a message with no content, which no provider accepts.
    pub messages: Vec<RequestMessage>,

    /// What this turn's last round reported, or `None` if no round reported anything.
    ///
    /// Not pre-merged with what was passed in, so "reported nothing" stays distinct from
    /// "reported what you already knew", and not enough on its own — [`withheld`] has to
    /// be threaded back too.
    ///
    /// [`withheld`]: Self::withheld
    pub usage: Option<PromptUsage>,

    /// How many of the oldest history messages the last request left out.
    ///
    /// `0` covers three cases a caller cannot tell apart: compaction off, on and under
    /// budget with nothing carried in, or over budget with nothing it could legally
    /// withhold.
    pub withheld: usize,

    /// What ended the turn, which [`messages`] cannot show.
    ///
    /// [`messages`]: Self::messages
    pub stop: TurnStop,
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
}

/// The bounds one turn runs within.
///
/// The two numeric defaults sit at the tighter end of plausible: too tight announces
/// itself the first time real work dies, too loose silently fails to catch the runaway.
#[derive(Debug, Clone, Copy)]
pub struct TurnLimits {
    /// How many times the model may be asked within one turn.
    ///
    /// A turn re-enters once per batch of tool calls, so this bounds how far a looping or
    /// injected-into model can drive tool execution. Reaching it ends the turn as a
    /// [`TurnStop::RoundLimit`] carrying the work it did, not a quiet stop.
    pub max_rounds: usize,

    /// How long one round may spend streaming before the turn is abandoned.
    ///
    /// Bounds one round's *consumption*, which `sandbx-providers` leaves to a caller: its
    /// own read timeout resets on every chunk, so a connection that stays warm while
    /// producing nothing is not bounded by it.
    ///
    /// Not a bound on the turn: nothing bounds a tool call in wall-clock terms, and an
    /// outer deadline would not help, since `spawn_blocking` cannot be cancelled (#26).
    pub stream_timeout: std::time::Duration,

    /// Whether to withhold the oldest history from a request that has outgrown a
    /// budget, and how much to keep.
    ///
    /// Off by default, and the only bound here that is lossy: the others refuse to go on
    /// when hit, where this one quietly sends the model less. `None` means a long
    /// conversation eventually dies on the provider's context-length error.
    pub compaction: Option<Compaction>,
}

impl Default for TurnLimits {
    fn default() -> Self {
        Self {
            max_rounds: 8,
            // The pressure point is a long extended-thinking generation.
            stream_timeout: std::time::Duration::from_secs(300),
            compaction: None,
        }
    }
}

/// Run one turn, accumulating its event stream into replayable messages.
///
/// The loop itself is `context/guide-turn-loop.md`; below is what the signature does not
/// show. All three closures are generics rather than `dyn`, which is not `Send` and would
/// make this future unspawnable; `AsyncFnMut` then leaves the future unnamed, so a
/// *generic* wrapper cannot add its own `Send` bound to it.
///
/// Every event reaches `observe` in arrival order before being accumulated, so one pass
/// serves both a renderer's increments and the replayable form. Re-entry keys off the
/// *presence* of tool calls, never `StopReason::ToolUse`, which is nullable on the wire.
///
/// Reasoning blocks live for the length of one turn: every round after the first replays
/// the ones before it, which is what the provider requires inside a tool-use turn, and
/// [`TurnOutcome::messages`] carries none, which is what keeps a signature out of a
/// caller's history and off its disk. A cut that deepens mid-turn drops the reasoning
/// already sent, that prefix no longer being the one it was signed against. See
/// `context/decision-thinking-replay.md`.
///
/// Compaction is off unless [`TurnLimits::compaction`] says otherwise, and needs both
/// `observed = outcome.usage.or(observed)` *and* `withheld = outcome.withheld` threaded
/// back. It narrows the request, never [`TurnOutcome::messages`].
///
/// `approve` is the only thing between the model asking for a tool and `sandbx-tools`
/// executing it, asked once per resolved call, before it runs. Neither an unknown name nor
/// one outside [`Turn::tools`] reaches it; both are refused above the gate, and an
/// [`ApprovalDecision::Deny`] is recoverable within [`TurnLimits::max_rounds`] rather than
/// a [`TurnError`]. It must not wait: it runs on the async task with no `spawn_blocking` of
/// its own, so waiting on an operator, a channel or a lock deadlocks the turn it is
/// deciding on a current-thread runtime. See `context/decision-approval-gate.md`.
///
/// Tools run on `spawn_blocking`, which cannot be cancelled: dropping this future still
/// lets the blocking task run to completion, so a turn abandoned mid-tool applies the
/// `write` anyway, recorded only in the audit trail (#26).
///
/// Needs a tokio runtime with the time driver enabled: the per-round bound is
/// `tokio::time::timeout`, which panics with "there is no timer running" otherwise.
/// `#[tokio::main]` and `Builder::new_*().enable_all()` enable it,
/// `Builder::new_current_thread().enable_io().build()` does not. The flavour is free,
/// since `spawn_blocking` needs only `rt`.
pub async fn run_turn<F, O, G>(
    mut open: F,
    turn: Turn<'_>,
    ctx: &ExecutionContext,
    mut observe: O,
    mut approve: G,
) -> Result<TurnOutcome, TurnError>
where
    F: AsyncFnMut(Prompt) -> Result<EventStream, ProviderError>,
    O: FnMut(&AgentEvent),
    G: FnMut(ToolCall<'_>) -> ApprovalDecision,
{
    // Built once: the offered set does not change between rounds.
    let definitions: Vec<ToolDefinition> = turn.tools.iter().copied().map(definition).collect();
    let mut produced: Vec<RequestMessage> = Vec::new();

    // The freshest measurement, the caller's until this turn makes one of its own.
    let mut observed = turn.observed;
    // What comes back, not seeded from `observed`: a caller has to tell "reported nothing"
    // from "reported what you already knew".
    let mut usage: Option<PromptUsage> = None;
    let mut cut = 0usize;
    // The carried floor until this turn plans its own cut, then that cut, so a floor no
    // legal boundary could meet is not re-asked for every round.
    let mut floor = turn.withheld;
    // A figure no plan has acted on — the caller's absent one included, which is what
    // holds the floor on a first round.
    let mut measured = true;
    // What the last request withheld, `None` before there was one.
    let mut sent_cut: Option<usize> = None;

    for _ in 0..turn.limits.max_rounds {
        if measured && let Some(policy) = turn.limits.compaction {
            // Within budget asks only to hold the floor; `None` would undo the cut
            // already paid for.
            let keep_recent =
                compact::over_budget(observed, policy.budget_tokens).then_some(policy.keep_recent);
            // A plan always contains the previous cut, so `unwrap_or` is the belt that
            // would stop a declined plan from restoring history.
            cut =
                compact::plan_cut(turn.history, produced.len(), keep_recent, floor).unwrap_or(cut);
            floor = cut;
            measured = false;
        }
        let withheld = cut;

        // A reasoning block is valid only against the messages that preceded it, so a
        // deepened cut invalidates every one already sent. Dropping the oldest reasoning
        // is the one edit the provider's check permits; leaving it in is a rejected
        // request.
        if sent_cut.is_some_and(|previous| previous != withheld) {
            drop_thinking(&mut produced);
        }
        sent_cut = Some(withheld);

        let mut messages = turn.history[withheld..].to_vec();
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

        // Only the consumption: opening the stream is bounded by the provider's own
        // connect and read timeouts.
        let round = tokio::time::timeout(
            turn.limits.stream_timeout,
            accumulate(&mut stream, &mut observe),
        )
        .await
        .map_err(|_| TurnError::TimedOut {
            after: turn.limits.stream_timeout,
        })??;

        // Before any exit below: a round's counts are worth reporting even when that
        // round is the one that ends the turn.
        if let Some(reported) = round.usage {
            usage = Some(reported);
            observed = Some(reported);
            measured = true;
        }
        let blocks = round.blocks;

        // The API rejects an empty content array, and a blockless message would
        // invalidate every later request.
        if blocks.is_empty() {
            // Unless a `tool_result` is waiting to be answered; see `EndedMidToolUse`.
            if matches!(produced.last(), Some(last) if matches!(last.role, Role::User)) {
                return Err(TurnError::EndedMidToolUse);
            }

            return Ok(outcome(produced, usage, withheld, TurnStop::Answered));
        }

        // Before the assistant turn is pushed: answering borrows the blocks, pushing
        // moves them.
        let results = answer_calls(&blocks, ctx, turn.tools, &mut approve).await?;

        produced.push(RequestMessage {
            role: Role::Assistant,
            content: blocks,
        });

        if results.is_empty() {
            return Ok(outcome(produced, usage, withheld, TurnStop::Answered));
        }

        produced.push(RequestMessage {
            role: Role::User,
            content: results,
        });
    }

    // Returned rather than dropped: every prefix of this transcript ends on an unanswered
    // `tool_result` too, or on a `tool_use` with nothing answering it, so no truncation of
    // it reads as a finished turn. `stop` is what says it is not one.
    Ok(outcome(
        produced,
        usage,
        // `cut`, the loop's `withheld` having gone out of scope with it; the two hold the
        // same figure, since a cut only ever deepens at the top of a round.
        cut,
        TurnStop::RoundLimit {
            rounds: turn.limits.max_rounds,
        },
    ))
}

/// The one exit from [`run_turn`], so no path can return reasoning to a caller.
fn outcome(
    mut produced: Vec<RequestMessage>,
    usage: Option<PromptUsage>,
    withheld: usize,
    stop: TurnStop,
) -> TurnOutcome {
    drop_thinking(&mut produced);
    TurnOutcome {
        messages: produced,
        usage,
        withheld,
        stop,
    }
}

/// Drop every reasoning block, and any turn left with nothing else in it.
///
/// Both kinds go together: the provider checks for a gap, so keeping redacted reasoning
/// while dropping the rest is worse than dropping all of it. An emptied turn can only be
/// the last one — a round that produced nothing but reasoning asks for no tools, which
/// ends the loop — so removing it cannot leave two user turns adjacent.
fn drop_thinking(messages: &mut Vec<RequestMessage>) {
    for message in messages.iter_mut() {
        message.content.retain(|block| !block.is_thinking());
    }
    messages.retain(|message| !message.content.is_empty());
}
