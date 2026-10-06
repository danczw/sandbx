//! Naive compaction: withhold the oldest history from a request that has grown past a
//! caller's token budget.
//!
//! No summarisation model, just a bounded window. The API rejects a conversation that
//! does not open on a user turn, two consecutive user turns, an orphaned `tool_result`,
//! and an empty content array — so only a *prefix* is dropped and the whole question
//! collapses onto the new first message, which [`opens_a_request`] decides. In a
//! tool-heavy transcript that makes the legal cut points exactly the human prose turns;
//! see `context/guide-turn-loop.md`.

use sandbx_providers::{ContentBlock, RequestMessage, Role};

use crate::PromptUsage;

/// When to withhold history, and how much to keep.
///
/// Opt-in because the right value depends on the model named in the request, which
/// `Turn::model` carries as a freeform string with no context-window table behind it.
#[derive(Debug, Clone, Copy)]
pub struct Compaction {
    /// Compaction fires once the last *measured* prompt exceeded this.
    ///
    /// Measured, not predicted: what the provider reported for the request already sent,
    /// which excludes the reply and the tool results after it. Set it below the model's
    /// window with room to spare.
    pub budget_tokens: u32,

    /// How many of the newest messages to aim to keep.
    ///
    /// A target in both directions, not a guarantee: the cut has to land on a legal
    /// boundary, and this turn's own messages are never withheld, so a small value cannot
    /// force them out. Counted over the whole request.
    pub keep_recent: usize,
}

/// Whether the last measured prompt was over budget.
///
/// A `None` measurement never fires: guessing would compact a conversation that may be
/// two messages long.
pub(crate) fn over_budget(observed: Option<PromptUsage>, budget_tokens: u32) -> bool {
    observed.is_some_and(|usage| usage.prompt_tokens() > u64::from(budget_tokens))
}

/// How many of `history`'s oldest messages to withhold, or `None` to withhold none.
///
/// Pure and total: every lookup goes through `get` and every subtraction is guarded, so
/// it cannot panic, diverge, or return a cut that leaves the request invalid or empty.
///
/// `produced` is a *count*, not a slice, so no cut can reach the current turn's own
/// messages. Load-bearing twice: the request's cached prefix stays a prefix as the turn
/// goes round, and a turn can never be made to re-ask for a tool whose result it withheld
/// from itself.
///
/// Two postconditions `run_turn` leans on: every `Some` satisfies [`opens_a_request`], and
/// the cut is never shallower than a `floor` that is itself a legal boundary. One that is
/// not is met as closely as the law allows, which can land below it; one at or past the end
/// of the history is dropped — see the clamp below.
///
/// `keep_recent` is `None` within budget, which holds the floor and deepens no further.
/// `Some` asks for the cut the cap implies, then, because an over-budget turn that cannot
/// be compacted still has to run:
///
/// 1. the shallowest legal cut at or after the target;
/// 2. failing that, the deepest legal cut below it — shedding less than asked beats
///    shedding nothing, and the next turn re-measures;
/// 3. failing that, `None`, uncompacted: erroring would make an opt-in optimisation a
///    turn-killer, and cutting anyway sends a request the API is certain to reject.
///
/// Why the floor exists is `context/guide-turn-loop.md`.
pub(crate) fn plan_cut(
    history: &[RequestMessage],
    produced: usize,
    keep_recent: Option<usize>,
    floor: usize,
) -> Option<usize> {
    // The scans stop short of `history.len()`: cutting there would open the request on
    // `produced[0]`, always an assistant message, or on nothing at all.
    let ceiling = history.len();
    // A floor at or past the end names no message. Clamping it onto the end would withhold
    // all but the newest exchange, permanently, since that cut becomes the next floor.
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
            // From the target, not the floor: when the floor is not itself a legal
            // boundary this is the only scan that can reach below it.
            (1..target).rev().find(|&cut| opens_a_request(history, cut))
        })
}

/// Whether `history[cut..]` followed by the turn's own messages is still a conversation
/// the API accepts, given that the uncut one already was.
///
/// Three conditions on the message that would become the first; the module docs say why
/// these three are the whole of it:
///
/// 1. `Role::User`. A cut onto an assistant message also strands its `tool_use` blocks —
///    their answers sit in the message after it, which would then be a second user turn.
/// 2. No `ToolResult` block, whose `ToolUse` is in the withheld `history[cut - 1]` — the
///    clause that makes an arbitrary index illegal.
/// 3. Non-empty content, which only a caller's own history can hold.
///
/// `cut == 0` is false because it withholds nothing, so a `Some` from [`plan_cut`] always
/// means something was actually withheld.
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
