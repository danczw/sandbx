//! Naive compaction: withhold the oldest history from a request that has grown past a
//! caller's token budget.
//!
//! No summarisation model, just a bounded window. The API will not accept an arbitrary
//! prefix drop: it rejects a conversation that does not open on a user turn, two
//! consecutive user turns, a `tool_result` whose `tool_use` is absent (or the reverse),
//! and an empty content array.
//!
//! Only a *prefix* is ever dropped, so every interior pair survives and the whole
//! question collapses onto the new first message, which [`opens_a_request`] decides. In a
//! tool-heavy transcript that makes the legal cut points exactly the human prose turns —
//! one per exchange, not one per message.

use sandbx_providers::{ContentBlock, RequestMessage, Role};

use crate::PromptUsage;

/// When to withhold history, and how much to keep.
///
/// Opt-in, and the only bound in this crate that is off by default: the others refuse to
/// proceed when hit, where this one quietly sends the model less than it was given. The
/// right value depends on the model named in the request, which `Turn::model` carries as
/// a freeform string with no context-window table behind it.
#[derive(Debug, Clone, Copy)]
pub struct Compaction {
    /// Compaction fires once the last *measured* prompt exceeded this.
    ///
    /// Measured, not predicted: compared against what the provider reported for the
    /// request already sent, which excludes the reply to it and the tool results that
    /// follow. So set it below the model's window with room to spare.
    pub budget_tokens: u32,

    /// How many of the newest messages to aim to keep.
    ///
    /// A target rather than a guarantee, in both directions: the cut has to land on a
    /// legal boundary, and the current turn's own messages are never withheld, so a
    /// small value cannot force them out. Counted over the whole request — the caller's
    /// history plus the turn's own work.
    pub keep_recent: usize,
}

/// Whether the last measured prompt was over budget.
///
/// A `None` measurement never fires: a turn's first round has no figure to go on, and
/// guessing would compact a conversation that may be two messages long. That bounds the
/// *round*, not the turn — `run_turn` feeds each round's own report back in.
pub(crate) fn over_budget(observed: Option<PromptUsage>, budget_tokens: u32) -> bool {
    observed.is_some_and(|usage| usage.prompt_tokens() > u64::from(budget_tokens))
}

/// How many of `history`'s oldest messages to withhold, or `None` to withhold none.
///
/// Pure and total: two bounded index scans, every lookup through `get` and every
/// subtraction guarded. It cannot panic, cannot diverge, and cannot return a cut that
/// leaves the request invalid or empty.
///
/// `produced` is a *count*, not a slice, so no cut returned here can reach the current
/// turn's own messages. Load-bearing twice: the request's cached prefix stays a prefix
/// as the turn goes round again, and a turn can never be made to re-ask for a tool whose
/// result it withheld from itself.
///
/// Two postconditions `run_turn` leans on: every `Some` satisfies [`opens_a_request`],
/// and the cut is never shallower than a `floor` that is itself a legal boundary. A floor
/// that is not one is met as closely as the law allows instead, which can land below it.
///
/// `floor` is what the previous turn withheld. Without it the mechanism oscillates and
/// bounds nothing: the figure a caller measures is the cost of the *already compacted*
/// request, so the turn after a successful compaction reads under budget, puts the whole
/// history back, and sends more than the turn that just triggered. Carrying a count
/// forward is exact rather than approximate because appending to a history does not move
/// the indices of its prefix.
///
/// `keep_recent` is `None` when the last measured prompt was *within* budget: hold the
/// floor and deepen no further. `Some` asks for the cut the cap implies, never shallower
/// than the floor. Then, because an over-budget turn that cannot be compacted still has
/// to run:
///
/// 1. the shallowest legal cut at or after the target;
/// 2. failing that, the deepest legal cut below the target — the long unbroken tool
///    chain, where shedding less than asked still beats shedding nothing and the next
///    turn re-measures;
/// 3. failing that, `None`: the request goes out uncompacted.
///
/// Rung 3 rather than erroring, which would turn an opt-in optimisation into a
/// turn-killer, or cutting anyway, which sends a request the API is certain to reject.
/// The provider's own context-length error stays the real backstop — the honest limit of
/// compaction this naive, which sheds whole exchanges and so cannot shed a single
/// enormous one at all.
///
/// A `floor` no boundary can meet means a caller rewrote its history rather than
/// appending to it. While it still names a message, rung 2 sheds to the deepest boundary
/// below it rather than dropping it and sending the history whole, which would hand that
/// caller `withheld: 0` and restart compaction from zero; it also pushes the target past
/// every boundary, so the cut can keep less than `keep_recent` asked for. At or past the
/// end of the history it is dropped instead — see the clamp below.
pub(crate) fn plan_cut(
    history: &[RequestMessage],
    produced: usize,
    keep_recent: Option<usize>,
    floor: usize,
) -> Option<usize> {
    // The scans stop short of `history.len()`: cutting there would open the request on
    // `produced[0]`, which `run_turn` always pushes as an assistant message, or on
    // nothing at all when the turn has produced nothing.
    let ceiling = history.len();
    // A floor at or past the end names no message, so there is nothing to meet. Clamping it
    // onto the end would meet it from the deepest boundary in the transcript and withhold
    // all but the newest exchange — permanently, since that cut becomes the next floor.
    let floor = if floor >= ceiling { 0 } else { floor };

    let target = match keep_recent {
        // Saturating, so a `keep_recent` larger than the conversation lands on 0 and
        // withholds nothing rather than wrapping.
        Some(keep) => (history.len() + produced)
            .saturating_sub(keep)
            .min(ceiling)
            .max(floor),
        None => floor,
    };

    // Nothing held and nothing to shed.
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
/// 1. `Role::User`. The API rejects a conversation opening on the assistant, and a cut
///    onto an assistant message would strand its `tool_use` blocks as well — their
///    answers sit in the message after it, which would then be a second user turn.
/// 2. No `ToolResult` block. Its matching `ToolUse` is in the withheld `history[cut - 1]`,
///    and an orphaned `tool_result` is rejected. This is the clause that makes an
///    arbitrary index illegal.
/// 3. Non-empty content, which the API rejects. `run_turn` never builds one, so this
///    guards only a caller's own history, by declining to cut onto it rather than
///    repairing it.
///
/// `cut == 0` is false because it withholds nothing, so a `Some` from [`plan_cut`]
/// always means something was actually withheld.
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
