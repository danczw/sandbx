//! One turn: the round loop, the public types it is driven by, and the compaction
//! threading those types carry.
//!
//! Rebuilding a round's message is `accumulate`; running what it asked for is `tools`.

use sandbx_providers::{
    AgentEvent, EventStream, MessagesRequest, ProviderError, RequestMessage, Role, ToolDefinition,
};
use sandbx_tools::{BuiltinTool, ExecutionContext};

use crate::{ApprovalDecision, Compaction, ToolCall, TurnError, compact};

mod accumulate;
mod tools;

use accumulate::accumulate;
use tools::{answer_calls, definition};

/// What to ask the model for.
///
/// Borrows the history: [`run_turn`] hands back the turns it produced rather than
/// appending to a caller's list.
pub struct Turn<'a> {
    /// The model to ask. A freeform string, as `MessagesRequest` takes it.
    pub model: String,
    /// The cap on the model's reply. This crate has no default opinion.
    pub max_tokens: u32,
    /// The system prompt, omitted from the request entirely when `None`.
    pub system: Option<String>,
    /// The built-ins to offer. An empty slice offers none, not all of them.
    pub tools: &'a [BuiltinTool],
    /// The conversation so far, oldest first.
    pub history: &'a [RequestMessage],
    /// The bounds this turn runs within.
    pub limits: TurnLimits,

    /// What the previous turn's request cost: [`TurnOutcome::usage`] threaded back as
    /// `observed = outcome.usage.or(observed)`.
    ///
    /// Carried in because a turn's first round has to build its request before any figure
    /// for it exists. Half of what makes [`TurnLimits::compaction`] work; [`withheld`] is
    /// the other half and neither works alone. `None` bounds only the first round: every
    /// turn compacts on its own figures once it has one, whatever it was given here.
    ///
    /// [`withheld`]: Self::withheld
    pub observed: Option<PromptUsage>,

    /// How many of `history`'s oldest messages the previous turn left out of its
    /// request. [`TurnOutcome::withheld`], threaded back unchanged.
    ///
    /// A floor, not an instruction: this turn may withhold more, never less — unless the
    /// count no longer names a legal cut point, in which case it withholds as much as the
    /// law allows and [`TurnOutcome::withheld`] can come back smaller. Without the floor
    /// compaction bounds nothing, because [`observed`] measures the *already compacted*
    /// request — so the turn after a compaction reads under budget, puts the whole history
    /// back, and sends more than the turn that triggered. Carrying a count is exact only
    /// because appending to history does not move its prefix's indices; a caller that
    /// rewrites history invalidates it, and `compact::plan_cut` absorbs that by cutting to
    /// the deepest boundary below it, or dropping it once it is past the history's end.
    ///
    /// [`observed`]: Self::observed
    pub withheld: usize,
}

/// The prompt-side token counters of the last `AgentEvent::Usage` a turn reported.
///
/// Every field is `Option` because the API may omit any of them, and `None` means "not
/// reported", which stays distinguishable from a reported zero. `output_tokens` is
/// absent: compaction asks how large the *request* was, and `observe` sees the whole
/// event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PromptUsage {
    /// Tokens in the request, excluding anything served from cache.
    pub input_tokens: Option<u32>,
    /// Tokens read from the prompt cache.
    pub cache_read_input_tokens: Option<u32>,
    /// Tokens written to the prompt cache.
    pub cache_creation_input_tokens: Option<u32>,
}

impl PromptUsage {
    /// The whole prompt, as the provider counted it.
    ///
    /// All three counters summed: a cache read is a real prompt token charged against the
    /// context window, so `input_tokens` alone would under-read a cached conversation by
    /// an order of magnitude. `u64` because three saturated counters overflow a `u32` and
    /// these figures come off the wire. An unreported counter sums as zero, since the API
    /// omits the cache fields when no cache was involved and reading that as "unknown"
    /// would disable compaction for every uncached request.
    #[must_use]
    pub fn prompt_tokens(&self) -> u64 {
        u64::from(self.input_tokens.unwrap_or(0))
            + u64::from(self.cache_read_input_tokens.unwrap_or(0))
            + u64::from(self.cache_creation_input_tokens.unwrap_or(0))
    }
}

/// What one turn came to: its messages, what the request cost, and whether anything
/// had to be left out to fit.
#[derive(Debug)]
pub struct TurnOutcome {
    /// The turns this call produced, oldest first, to be appended to the caller's
    /// history.
    ///
    /// Always complete. Compaction narrows the *request*, never this: a caller whose
    /// stored history lost whatever the model was not shown would compound that loss
    /// every turn.
    pub messages: Vec<RequestMessage>,

    /// What this turn's last round reported, or `None` if no round reported anything.
    ///
    /// Thread it into the next turn's [`Turn::observed`] with
    /// `observed = outcome.usage.or(observed)`. Not pre-merged with what was passed in, so
    /// "reported nothing" stays distinct from "reported what you already knew". Not enough
    /// on its own: once compaction has fired it measures the compacted request, so
    /// [`withheld`] has to be threaded back too.
    ///
    /// [`withheld`]: Self::withheld
    pub usage: Option<PromptUsage>,

    /// How many of the oldest history messages the last request left out.
    ///
    /// Thread it into the next turn's [`Turn::withheld`] unchanged, where it becomes the
    /// floor the next cut may deepen but not undo. `0` covers three cases a caller cannot
    /// tell apart: compaction off, on and under budget with nothing carried in, or over
    /// budget with nothing it could legally withhold.
    ///
    /// Smaller than the [`Turn::withheld`] that went in only when that count had stopped
    /// naming a legal cut point, which takes a caller rewriting its history.
    pub withheld: usize,
}

/// The bounds one turn runs within.
///
/// Both defaults sit at the tighter end of plausible: too tight announces itself the
/// first time real work dies, too loose silently fails to catch the runaway.
#[derive(Debug, Clone, Copy)]
pub struct TurnLimits {
    /// How many times the model may be asked within one turn.
    ///
    /// A turn re-enters once per batch of tool calls, so this bounds how far a looping or
    /// injected-into model can drive tool execution. Reaching it is a
    /// [`TurnError::RoundLimit`], not a quiet stop.
    pub max_rounds: usize,

    /// How long one round may spend streaming before the turn is abandoned.
    ///
    /// Bounds the *consumption* of one round, which `sandbx-providers` leaves to a caller:
    /// its own read timeout bounds inactivity between chunks and resets on every one, so a
    /// connection that stays warm while producing nothing is not bounded by it.
    ///
    /// Nothing bounds a tool call in wall-clock terms, so a turn has no total time bound.
    /// `ExecutionContext::timeout` covers `bash`, where the sandbox spawns a process, and
    /// none of the six in-process tools; those are bounded by *work* instead, `ToolLimits`
    /// capping files walked and bytes read. An outer deadline would not help: tools run on
    /// `spawn_blocking`, which cannot be cancelled, so the work continues after the future
    /// is dropped (#26).
    pub stream_timeout: std::time::Duration,

    /// Whether to withhold the oldest history from a request that has outgrown a
    /// budget, and how much to keep.
    ///
    /// Off by default, and the only bound here that is lossy: the others refuse to go on
    /// when hit, where this one quietly sends the model less than it was given. See
    /// [`Compaction`] for why the budget is a caller's to set. `None` means a long
    /// conversation eventually dies on the provider's own context-length error.
    pub compaction: Option<Compaction>,
}

impl Default for TurnLimits {
    fn default() -> Self {
        Self {
            max_rounds: 8,
            // The pressure point is a long extended-thinking generation.
            stream_timeout: std::time::Duration::from_secs(300),
            // Lossy, and model-specific. See the field.
            compaction: None,
        }
    }
}

/// Run one turn, accumulating its event stream into replayable messages.
///
/// `open` is a closure that opens a stream rather than a provider, so this is generic
/// over the *stream shape* and not over which client produced it: the real call is
/// `run_turn(|request| client.stream_chat(request), ..)`, and a test passes one that
/// replays canned events. `AsyncFnMut` leaves the returned future unnamed, so a *generic*
/// wrapper around `run_turn` cannot add its own `Send` bound to it. `observe` is a
/// generic for the mirror reason: `dyn FnMut` is not `Send`, so taking one would make
/// this future unspawnable.
///
/// Every event reaches `observe` in arrival order before being accumulated, so one pass
/// serves both a renderer's increments and the replayable form. `AgentEvent::Thinking`
/// reaches `observe` but never the returned messages: `ContentBlock` has no thinking
/// variant and the signature needed to replay one is discarded upstream (#85).
/// `AgentEvent::Usage` is accounting rather than content, so its counts come back on
/// [`TurnOutcome::usage`] instead of in the rebuilt history.
///
/// Compaction is off unless [`TurnLimits::compaction`] says otherwise. When the last
/// *measured* prompt was over budget the oldest history is left out of the request —
/// never out of [`TurnOutcome::messages`], which is always the whole turn. It needs both
/// `observed = outcome.usage.or(observed)` *and* `withheld = outcome.withheld` threaded
/// back: usage alone measures the already-compacted request and oscillates, see
/// [`Turn::withheld`].
///
/// The cut only ever deepens: within a turn it moves at most once per round that reported
/// a figure, and across turns the previous cut is the floor for the next. So the model is
/// never re-shown history it had lost. It is the only in-turn bound there is, since
/// `produced` grows the request as the turn goes round, and it is the reason a round that
/// reports nothing re-sends the same cut rather than deepening on a figure already acted
/// on. The cut can never reach the messages *this* turn produced, because
/// `compact::plan_cut` is handed their count rather than the messages, so a turn cannot
/// withhold the tool result it is waiting on. Whole exchanges are the only legal cut
/// points, so a single enormous one is not compactable at all and the provider's
/// context-length error stays the backstop.
///
/// `approve` is asked once per resolved call, before it runs, and is the only thing
/// between the model asking for a tool and `sandbx-tools` executing it. Mandatory rather
/// than defaulted, so a caller cannot acquire a gate-less loop by omission; a closure for
/// the same reason as `observe`. An [`ApprovalDecision::Deny`] answers the model with its
/// `reason` as a `tool_result` marked `is_error` and runs nothing, so a refusal is
/// recoverable — the model may answer in prose or try a tool the gate allows, within
/// [`TurnLimits::max_rounds`]. A name no tool answers to never reaches it, and nor does
/// one outside [`Turn::tools`]: both are refused above the gate, so a closure never has to
/// invent a verdict for a call the caller never offered.
///
/// **`approve` must not wait.** It is called on the async task, with no `spawn_blocking`
/// of its own, so a gate that waits — on an operator, a channel, a lock — stalls every
/// other task on the runtime, and on a current-thread one deadlocks the turn it is
/// deciding. A bounded write is not that. A decision that has to be awaited belongs to a
/// caller that owns the runtime, made before `run_turn` is entered rather than inside it.
///
/// Tools run on `spawn_blocking`, which cannot be cancelled: dropping this future drops the
/// `JoinHandle` while the blocking task runs to completion, so a turn abandoned mid-tool
/// still applies the `write`, recorded only in the audit trail (#26). That is also why
/// `approve` is consulted before the spawn rather than racing it.
///
/// Needs a tokio runtime with the time driver enabled: the per-round bound is
/// `tokio::time::timeout`, which panics with "there is no timer running" otherwise.
/// `#[tokio::main]` and `Builder::new_*().enable_all()` enable it,
/// `Builder::new_current_thread().enable_io().build()` does not; the flavour is free,
/// since `spawn_blocking` needs only `rt`.
///
/// The turn re-enters on the *presence* of tool calls, never on `StopReason::ToolUse`: a
/// stop reason is nullable on the wire, so a round can arrive with tool calls and
/// `StopReason::Unspecified`, and keying off the reason would drop them silently. A tool
/// that fails does not end the turn — it comes back as a `tool_result` marked `is_error`;
/// see [`TurnError`] for where the line is drawn.
pub async fn run_turn<F, O, G>(
    mut open: F,
    turn: Turn<'_>,
    ctx: &ExecutionContext,
    mut observe: O,
    mut approve: G,
) -> Result<TurnOutcome, TurnError>
where
    F: AsyncFnMut(MessagesRequest) -> Result<EventStream, ProviderError>,
    O: FnMut(&AgentEvent),
    G: FnMut(ToolCall<'_>) -> ApprovalDecision,
{
    // Built once: the offered set does not change between rounds.
    let definitions: Vec<ToolDefinition> = turn.tools.iter().copied().map(definition).collect();
    let mut produced: Vec<RequestMessage> = Vec::new();

    // The freshest measurement, the caller's until this turn makes one of its own.
    let mut observed = turn.observed;
    // This turn's own latest, which is what comes back. Not seeded from `observed`: a
    // caller has to tell "reported nothing" from "reported what you already knew".
    let mut usage: Option<PromptUsage> = None;
    // How much history this round leaves out; `measured` carries "a plan is due", so 0
    // means only that nothing is withheld.
    let mut cut = 0usize;
    // The carried floor until this turn plans its own cut, then that cut: a floor no legal
    // boundary could meet is not re-asked for every round.
    let mut floor = turn.withheld;
    // A figure no plan has acted on. The caller's counts as one, and so does its absence —
    // planning on `None` is what holds the floor on a first round.
    let mut measured = true;

    for _ in 0..turn.limits.max_rounds {
        if measured && let Some(policy) = turn.limits.compaction {
            // Over budget asks to deepen; within budget asks only to hold the floor.
            // `None` is not "do not compact" — a conversation already cut stays cut, or
            // the cut it paid for is undone.
            let keep_recent =
                compact::over_budget(observed, policy.budget_tokens).then_some(policy.keep_recent);
            // A plan always contains the previous cut, so `unwrap_or` is a belt: it is
            // what would stop a declined plan from restoring history.
            cut =
                compact::plan_cut(turn.history, produced.len(), keep_recent, floor).unwrap_or(cut);
            floor = cut;
            measured = false;
        }
        let withheld = cut;

        let mut messages = turn.history[withheld..].to_vec();
        messages.extend_from_slice(&produced);

        let request = MessagesRequest {
            model: turn.model.clone(),
            max_tokens: turn.max_tokens,
            system: turn.system.clone(),
            messages,
            tools: definitions.clone(),
        };

        let mut stream = open(request).await.map_err(TurnError::Provider)?;

        // Only the consumption is wrapped. Opening the stream is the provider's own
        // request, already bounded by its connect and read timeouts.
        let round = tokio::time::timeout(
            turn.limits.stream_timeout,
            accumulate(&mut stream, &mut observe),
        )
        .await
        .map_err(|_| TurnError::TimedOut {
            after: turn.limits.stream_timeout,
        })??;

        // Recorded before any exit below: a round's counts are worth reporting even when
        // that round is the one that ends the turn.
        if let Some(reported) = round.usage {
            usage = Some(reported);
            observed = Some(reported);
            measured = true;
        }
        let blocks = round.blocks;

        // The API rejects an empty content array, so a round that produced nothing appends
        // nothing: a blockless message would invalidate every later request.
        if blocks.is_empty() {
            // Unless a `tool_result` is waiting to be answered. Handing that back as a
            // finished turn breaks the request *after* this one: a caller appends its own
            // user message, and the API rejects two consecutive user turns.
            if matches!(produced.last(), Some(last) if matches!(last.role, Role::User)) {
                return Err(TurnError::EndedMidToolUse);
            }

            return Ok(TurnOutcome {
                messages: produced,
                usage,
                withheld,
            });
        }

        // Answered before the assistant turn is pushed: answering borrows the blocks and
        // pushing moves them.
        let results = answer_calls(&blocks, ctx, turn.tools, &mut approve).await?;

        produced.push(RequestMessage {
            role: Role::Assistant,
            content: blocks,
        });

        if results.is_empty() {
            return Ok(TurnOutcome {
                messages: produced,
                usage,
                withheld,
            });
        }

        produced.push(RequestMessage {
            role: Role::User,
            content: results,
        });
    }

    // Still wanting tools run. `produced` is dropped rather than returned: it ends in
    // a tool_result the model never answered, which would read as a finished turn.
    Err(TurnError::RoundLimit {
        rounds: turn.limits.max_rounds,
    })
}
