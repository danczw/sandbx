//! Naive compaction: withhold the oldest history from a request that has grown past a
//! caller's token budget.
//!
//! No summarisation model, just a bounded window. The API rejects anything but a user-turn
//! opener — two user turns running, an orphaned `tool_result`, or empty content — so only a
//! *prefix* drops, onto the new first message, which [`opens_a_request`] decides; that makes
//! the legal cut points exactly the human prose turns. See `context/guide-turn-loop.md`.

use sandbx_providers::{ContentBlock, RequestMessage, Role};

use crate::PromptUsage;

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

/// Whether the last measured prompt was over budget.
///
/// A `None` measurement never fires: guessing would compact a conversation that may be two
/// messages long.
pub(crate) fn over_budget(observed: Option<PromptUsage>, budget_tokens: u32) -> bool {
    observed.is_some_and(|usage| usage.prompt_tokens() > u64::from(budget_tokens))
}

/// How many of `history`'s oldest messages to withhold, or `None` to withhold none.
///
/// Pure and total: every lookup goes through `get`, every subtraction guarded, so it cannot
/// panic, diverge, or return an invalid or empty cut. `produced` is a *count*, not a slice,
/// so no cut can reach the current turn's own messages — keeping the cached prefix a prefix,
/// and never making a turn re-ask for a tool whose result it withheld from itself. Two
/// postconditions `run_turn` leans on: every `Some` satisfies [`opens_a_request`], and the
/// cut is never shallower than a `floor` that is itself a legal boundary — met as closely as
/// the law allows otherwise, dropped past the end of the history (see the clamp below).
///
/// `keep_recent` is `None` within budget, holding the floor. `Some` asks for the cut the cap
/// implies, falling back in order when over budget but uncompactable: the shallowest legal
/// cut at or after the target; failing that, the deepest legal cut below it, since shedding
/// less beats nothing and the next turn re-measures; failing that, `None` — erroring would
/// turn an opt-in optimisation into a turn-killer, and cutting anyway is certain to be
/// rejected. Why the floor exists is `context/guide-turn-loop.md`.
pub(crate) fn plan_cut(
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

    let target = match keep_recent {
        // Saturating, so a `keep_recent` past the conversation lands on 0, not wrapped.
        Some(keep) => (history.len() + produced)
            .saturating_sub(keep)
            .min(ceiling)
            .max(floor),
        None => floor,
    };

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
mod tests;
