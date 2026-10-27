//! Naive compaction: withhold the oldest history from a request that has grown past a
//! caller's token budget.
//!
//! No summarisation model, just a bounded window. The API rejects anything but a user-turn
//! opener — two user turns running, an orphaned `tool_result`, or empty content — so only a
//! *prefix* drops, onto the new first message, which `opens_a_request` decides; that makes
//! the legal cut points exactly the human prose turns. See `context/guide-turn-loop.md`.
//!
//! [`PromptUsage`] is declared here and not beside `Turn::observed`, where it reads as
//! belonging: the turn depends on compaction and not the reverse, so this is the side of
//! the edge it can sit on (#345).
//!
//! A crate and not a module of `sandbx-turn`: nothing here reaches the loop, so the edge
//! above is one cargo and `deny.toml` enforce rather than a convention (#356).

use sandbx_prompt::{ContentBlock, RequestMessage, Role};

/// When to withhold history, and how much to keep.
///
/// Opt-in because the right value depends on the model named in the request, which
/// `Turn::model` carries as a freeform string with no context-window table.
#[derive(Debug, Clone, Copy)]
pub struct Compaction {
    /// Compaction fires once the last *measured* prompt exceeded this.
    ///
    /// Measured, not predicted: what the provider reported for the request already sent,
    /// which excludes the reply and tool results after it. Set it below the model's window
    /// with room to spare.
    pub budget_tokens: u32,

    /// How many of the newest messages to aim to keep.
    ///
    /// A target in both directions, not a guarantee: the cut has to land on a legal boundary,
    /// and this turn's own messages are never withheld, so a small value can't force them
    /// out. Counted over the whole request.
    pub keep_recent: usize,
}

/// The prompt-side token counters of the last `AgentEvent::Usage` a turn reported.
///
/// `None` means "not reported", distinguishable from a reported zero. `output_tokens` is
/// absent: compaction asks how large the *request* was, and `observe` sees the whole event.
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
    /// context window. `u64` because three saturated counters overflow a `u32`. An unreported
    /// counter sums as zero rather than unknown — the API omits cache fields when unused, and
    /// reading that as unknown would disable compaction for every uncached request.
    #[must_use]
    pub fn prompt_tokens(&self) -> u64 {
        u64::from(self.input_tokens.unwrap_or(0))
            + u64::from(self.cache_read_tokens.unwrap_or(0))
            + u64::from(self.cache_write_tokens.unwrap_or(0))
    }
}

/// Whether the last measured prompt was over budget.
///
/// A `None` measurement never fires: guessing would compact a conversation that may be two
/// messages long.
pub fn over_budget(observed: Option<PromptUsage>, budget_tokens: u32) -> bool {
    observed.is_some_and(|usage| usage.prompt_tokens() > u64::from(budget_tokens))
}

/// How many of `history`'s oldest messages to withhold, or `None` to withhold none.
///
/// Pure and total: every lookup goes through `get`, every subtraction guarded, so it cannot
/// panic, diverge, or return an invalid or empty cut. `produced` is a *count*, not a slice,
/// so no cut can reach the current turn's own messages — keeping the cached prefix a prefix,
/// and never making a turn re-ask for a tool whose result it withheld from itself. Two
/// postconditions `run_turn` leans on: every `Some` satisfies `opens_a_request`, and the
/// cut is never shallower than a `floor` that is itself a legal boundary — met as closely as
/// the law allows otherwise, dropped past the end of the history (see the clamp below).
///
/// `keep_recent` is `None` within budget, holding the floor. `Some` asks for the cut the cap
/// implies, falling back in order when over budget but uncompactable: the shallowest legal
/// cut at or after the target; failing that, the deepest legal cut below it, since shedding
/// less beats nothing and the next turn re-measures; failing that, `None` — erroring would
/// turn an opt-in optimisation into a turn-killer, and cutting anyway is certain to be
/// rejected. Why the floor exists is `context/guide-turn-loop.md`.
pub fn plan_cut(
    history: &[RequestMessage],
    produced: usize,
    keep_recent: Option<usize>,
    floor: usize,
) -> Option<usize> {
    // The scans stop short of `history.len()`: cutting there opens the request on
    // `produced[0]`, always assistant, or on nothing.
    let ceiling = history.len();
    // A floor at or past the end names no message; clamping onto the end would withhold all
    // but the newest exchange permanently.
    let floor = if floor >= ceiling { 0 } else { floor };

    let target = keep_recent.map_or(floor, |keep| {
        // Saturating, so a `keep_recent` past the conversation lands on 0, not wrapped.
        (history.len() + produced)
            .saturating_sub(keep)
            .min(ceiling)
            .max(floor)
    });

    if target == 0 {
        return None;
    }

    (target..ceiling)
        .find(|&cut| opens_a_request(history, cut))
        .or_else(|| {
            // From the target, not the floor: when the floor isn't itself legal, only this
            // scan can reach below it.
            (1..target).rev().find(|&cut| opens_a_request(history, cut))
        })
}

/// Whether `history[cut..]` followed by the turn's own messages is still a conversation the
/// API accepts, given that the uncut one already was: three conditions on the message that
/// would become the first, and the module docs say why these are the whole of it.
///
/// 1. `Role::User`: a cut onto an assistant message strands `tool_use` blocks whose
///    answers would become a second user turn.
/// 2. No `ToolResult` block: its `ToolUse` sits in the withheld `history[cut - 1]`, the
///    clause that makes an arbitrary index illegal.
/// 3. Non-empty content, which only a caller's own history can hold.
///
/// `cut == 0` is false, so a `Some` from [`plan_cut`] always means something was withheld.
fn opens_a_request(history: &[RequestMessage], cut: usize) -> bool {
    cut > 0
        && history.get(cut).is_some_and(|first| {
            matches!(first.role, Role::User)
                && !first.content.is_empty()
                && !first
                    .content
                    .iter()
                    .any(|block| matches!(block, ContentBlock::ToolResult { .. }))
        })
}

#[cfg(test)]
#[path = "compact_tests.rs"]
mod tests;
