//! Naive compaction: withhold the oldest history from a request that has grown past a
//! caller's token budget.
//!
//! Naive in the planned sense — no summarisation model, just a bounded window. What
//! makes it less trivial than dropping the first `n` messages is that the API will not
//! accept an arbitrary prefix drop. Four shapes are rejected outright: a conversation
//! that does not open on a user turn, two consecutive user turns, a `tool_result` whose
//! `tool_use` is absent (or the reverse), and an empty content array.
//!
//! Because only a *prefix* is ever dropped, every interior pair survives untouched and
//! alternation inside the kept span is whatever it already was. So the whole question
//! collapses onto the new first message, which is what [`opens_a_request`] decides. The
//! consequence worth internalising: in a tool-heavy transcript the legal cut points are
//! exactly the human prose turns — one per exchange, not one per message.

use sandbx_providers::{ContentBlock, RequestMessage, Role};

use crate::PromptUsage;

/// When to withhold history, and how much to keep.
///
/// Opt-in, and the only bound in this crate that is off by default. The others refuse
/// to proceed when they are hit; this one quietly sends the model less than it was
/// given, and the right value for it depends on the model named in the request — which
/// `Turn::model` carries as a freeform string, with no context-window table behind it.
/// Only a caller knows what its own model's window is.
#[derive(Debug, Clone, Copy)]
pub struct Compaction {
    /// Compaction fires once the last *measured* prompt exceeded this.
    ///
    /// Measured, not predicted: it is compared against what the provider reported for
    /// the request that was already sent, which does not include the reply to it or the
    /// tool results that follow. So set it below the model's window with room to spare.
    pub budget_tokens: u32,

    /// How many of the newest messages to aim to keep.
    ///
    /// A target rather than a guarantee, in both directions. The cut has to land on a
    /// legal boundary, so honouring this exactly is usually impossible; and the current
    /// turn's own messages are never withheld, so a small value cannot force them out.
    /// Counted over the whole request — the caller's history plus the turn's own work —
    /// so the number means what it looks like it means.
    pub keep_recent: usize,
}

/// Whether the last measured prompt was over budget.
///
/// A `None` measurement never fires: a turn's first round has no figure to go on, and
/// guessing would compact a conversation that may be two messages long. That bounds the
/// *round*, not the turn — `run_turn` feeds each round's own report back in, so a turn
/// that started with nothing still compacts once it has measured itself.
pub(crate) fn over_budget(observed: Option<PromptUsage>, budget_tokens: u32) -> bool {
    observed.is_some_and(|usage| usage.prompt_tokens() > u64::from(budget_tokens))
}

/// How many of `history`'s oldest messages to withhold, or `None` to withhold none.
///
/// Pure and total: two bounded index scans, no allocation, no unbounded loop, every
/// lookup through `get` and every subtraction guarded. It cannot panic, cannot diverge,
/// and cannot return a cut that leaves the request invalid or empty.
///
/// `produced` is a *count*, not a slice, so no cut this function returns can reach the
/// current turn's own messages. Load-bearing twice over: the request's cached prefix
/// stays a prefix as the turn goes round again, and a turn can never be made to re-ask
/// for a tool whose result it withheld from itself.
///
/// # Why `floor`, and why the cut only ever deepens
///
/// `floor` is what the previous turn withheld, and the returned cut is never shallower
/// than it. Without that the whole mechanism oscillates and bounds nothing: the figure
/// a caller measures is the cost of the *already compacted* request, so the turn after
/// a successful compaction reads comfortably under budget, puts the whole history back,
/// and sends more than the turn that just triggered. Compaction would fire on alternate
/// turns while the uncompacted leg grew without limit.
///
/// Appending to a history does not move the indices of its prefix, so a cut that was
/// legal last turn still names the same message this turn — which is what makes
/// carrying it forward meaningful rather than approximate.
///
/// # The target, and the three rungs
///
/// `keep_recent` is `None` when the last measured prompt was *within* budget: hold the
/// floor and deepen no further. `Some` asks for the cut the cap implies, but never
/// shallower than the floor.
///
/// Then, because an over-budget turn that cannot be compacted still has to run:
///
/// 1. the shallowest legal cut at or after the target;
/// 2. failing that, the deepest legal cut between the floor and the target. This is the
///    long unbroken tool chain: nothing legal is deep enough, so shed less than asked
///    rather than nothing, and let the next turn re-measure;
/// 3. failing that, `None` — the request goes out uncompacted.
///
/// Rung 3 is deliberate. Erroring would turn an opt-in optimisation into a turn-killer;
/// cutting anyway sends a request the API is certain to reject, converting a request
/// that might have been too long into one that definitely fails, as an opaque
/// `TurnError::Provider`; and looking harder for a cut that provably does not exist is
/// the infinite loop. The provider's own context-length error stays the real backstop,
/// which is the honest limit of compaction this naive: it sheds whole exchanges, so a
/// single enormous exchange cannot be shed at all.
///
/// Reaching rung 3 with a non-zero `floor` means a caller threaded back a count its
/// history no longer supports — history was rewritten, not just appended to. Honouring
/// the floor is impossible then, so it is dropped rather than forced, and the request
/// goes out whole: too large is recoverable where invalid is not.
pub(crate) fn plan_cut(
    history: &[RequestMessage],
    produced: usize,
    keep_recent: Option<usize>,
    floor: usize,
) -> Option<usize> {
    // The scans stop short of `history.len()`: cutting there would open the request on
    // `produced[0]`, which `run_turn` always pushes as an assistant message, or on
    // nothing at all when the turn has produced nothing yet.
    let ceiling = history.len();
    let floor = floor.min(ceiling);

    let target = match keep_recent {
        // The saturating subtraction is what makes a `keep_recent` larger than the
        // conversation land on 0 and withhold nothing, rather than wrapping.
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
            (floor.max(1)..target)
                .rev()
                .find(|&cut| opens_a_request(history, cut))
        })
}

/// Whether `history[cut..]` followed by the turn's own messages is still a conversation
/// the API accepts, given that the uncut one already was.
///
/// Three conditions on the message that would become the first, and the module docs say
/// why these three are the whole of it:
///
/// 1. `Role::User`. The API rejects a conversation opening on the assistant, and a cut
///    onto an assistant message would strand its `tool_use` blocks as well — their
///    answers sit in the message after it, which would then be a second user turn.
/// 2. No `ToolResult` block. Its matching `ToolUse` is in `history[cut - 1]`, which is
///    being withheld, and an orphaned `tool_result` is rejected. This is the clause
///    that makes an arbitrary index illegal.
/// 3. Non-empty content. The API rejects an empty content array. `run_turn` never
///    builds one, so this guards only a caller's own history — and it guards by
///    declining to cut onto it, not by pretending to repair it.
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
mod tests {
    use super::*;

    /// A human prose turn: the only shape that is ever a legal cut point.
    fn user_text(text: &str) -> RequestMessage {
        RequestMessage {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: text.to_string(),
            }],
        }
    }

    /// An assistant turn asking for a tool.
    fn assistant_call(id: &str) -> RequestMessage {
        RequestMessage {
            role: Role::Assistant,
            content: vec![ContentBlock::ToolUse {
                id: id.to_string(),
                name: "read".to_string(),
                input: serde_json::json!({}),
            }],
        }
    }

    /// The user turn that answers one, which is never a legal cut point.
    fn user_result(id: &str) -> RequestMessage {
        RequestMessage {
            role: Role::User,
            content: vec![ContentBlock::ToolResult {
                tool_use_id: id.to_string(),
                content: "ok".to_string(),
                is_error: None,
            }],
        }
    }

    /// A shape `run_turn` never produces, which a caller editing its own history can.
    fn empty_user() -> RequestMessage {
        RequestMessage {
            role: Role::User,
            content: Vec::new(),
        }
    }

    /// One exchange: prose, a call, its answer, the assistant's reply.
    fn exchange(id: &str, prose: &str) -> Vec<RequestMessage> {
        vec![
            user_text(prose),
            assistant_call(id),
            user_result(id),
            RequestMessage {
                role: Role::Assistant,
                content: vec![ContentBlock::Text {
                    text: "done".to_string(),
                }],
            },
        ]
    }

    fn usage(input: Option<u32>, read: Option<u32>, creation: Option<u32>) -> PromptUsage {
        PromptUsage {
            input_tokens: input,
            cache_read_input_tokens: read,
            cache_creation_input_tokens: creation,
        }
    }

    /// The happy path, and the one that pins the search *direction*. Scanning forward
    /// from the target keeps the shallowest cut that still meets the cap; scanning
    /// backward would keep more than `keep_recent` and fail to get under budget.
    #[test]
    fn the_cut_lands_on_the_first_user_message_at_or_after_the_target() {
        let history = vec![
            user_text("one"),
            user_text("two"),
            user_text("three"),
            user_text("four"),
        ];

        assert_eq!(plan_cut(&history, 0, Some(2), 0), Some(2));
    }

    /// The central property. An orphaned `tool_result` is a hard API rejection, and in
    /// a tool-heavy transcript most indices are one — so the predicate has to walk past
    /// them rather than take the index arithmetic at face value.
    #[test]
    fn a_cut_onto_a_tool_result_is_refused_and_the_next_boundary_is_taken() {
        let mut history = exchange("a", "first");
        history.extend(exchange("b", "second"));

        // Index 2 is the `tool_result` answering `a`; the next legal boundary is the
        // prose turn that opens the second exchange.
        assert_eq!(plan_cut(&history, 0, Some(6), 0), Some(4));
    }

    /// The API rejects a conversation that does not open on a user turn, and a cut onto
    /// an assistant message strands its `tool_use` as well.
    #[test]
    fn a_cut_onto_an_assistant_message_is_refused() {
        let history = exchange("a", "first");

        // Indices 1 and 3 are assistant turns, 2 is a tool result: nothing is legal.
        assert_eq!(plan_cut(&history, 0, Some(1), 0), None);
    }

    /// Rung 2 of the ladder. The recent tail is one unbroken chain, so no legal cut is
    /// deep enough — shedding less than asked still beats shedding nothing, and the
    /// next turn re-measures and tries again.
    #[test]
    fn a_tail_that_is_one_unbroken_tool_chain_falls_back_to_an_earlier_boundary() {
        let mut history = vec![user_text("first"), assistant_call("a"), user_result("a")];
        history.push(user_text("second"));
        for id in ["b", "c", "d"] {
            history.push(assistant_call(id));
            history.push(user_result(id));
        }

        // Target is 8, but index 3 is the deepest legal boundary anywhere.
        assert_eq!(history.len(), 10);
        assert_eq!(plan_cut(&history, 0, Some(2), 0), Some(3));
    }

    /// Rung 3. Proves the no-legal-cut case declines rather than cutting anyway,
    /// erroring, or looping: an invalid request fails where an oversized one might not.
    #[test]
    fn a_history_whose_only_boundary_is_its_first_message_is_left_uncompacted() {
        let mut history = vec![user_text("first")];
        for id in ["a", "b", "c"] {
            history.push(assistant_call(id));
            history.push(user_result(id));
        }

        assert_eq!(plan_cut(&history, 0, Some(1), 0), None);
    }

    /// Guards the saturating-subtraction trap. The target lands on 0, and without the
    /// guard on that the forward scan cuts at the first boundary it finds, compacting a
    /// conversation the configuration said to keep whole.
    #[test]
    fn a_keep_recent_larger_than_the_conversation_withholds_nothing() {
        let history = vec![user_text("one"), user_text("two")];

        assert_eq!(plan_cut(&history, 0, Some(2), 0), None);
        assert_eq!(plan_cut(&history, 0, Some(99), 0), None);
        assert_eq!(plan_cut(&history, 1, Some(3), 0), None);
    }

    /// The degenerate configuration, given defined behaviour rather than rejected at
    /// construction — `Compaction` has public fields and no constructor to validate in.
    /// "As aggressive as legally possible" must still leave a sendable request.
    #[test]
    fn a_keep_recent_of_zero_cuts_to_the_newest_boundary_rather_than_emptying_it() {
        let history = vec![
            user_text("one"),
            user_text("two"),
            user_text("three"),
            user_text("four"),
        ];

        // Not 4: the scan stops short of `history.len()`, so the request keeps at least
        // the last history message.
        assert_eq!(plan_cut(&history, 0, Some(0), 0), Some(3));
    }

    /// The invariant behind "the request is never empty and never opens on the
    /// assistant's own output", swept over the shapes that could break it.
    #[test]
    fn no_plan_ever_withholds_the_whole_history() {
        let mut shapes = vec![
            vec![user_text("one")],
            vec![user_text("one"), user_text("two")],
            exchange("a", "first"),
            vec![empty_user(), user_text("two")],
        ];
        let mut long = exchange("a", "first");
        long.extend(exchange("b", "second"));
        shapes.push(long);

        for history in shapes {
            for produced in 0..4 {
                for floor in 0..4 {
                    for keep_recent in [None, Some(0), Some(1), Some(2), Some(3)] {
                        if let Some(cut) = plan_cut(&history, produced, keep_recent, floor) {
                            assert!(
                                cut < history.len(),
                                "withheld all {} of {history:?} at {keep_recent:?}/floor {floor}",
                                history.len()
                            );
                        }
                    }
                }
            }
        }
    }

    /// The type-level guarantee, checked behaviourally: growing the turn's own output
    /// only ever deepens the cut into history, never reaches past it.
    #[test]
    fn the_current_turns_own_messages_are_never_candidates() {
        let history = vec![
            user_text("one"),
            user_text("two"),
            user_text("three"),
            user_text("four"),
        ];

        for produced in 0..7 {
            let cut = plan_cut(&history, produced, Some(2), 0);
            assert!(
                cut.is_none_or(|cut| cut < history.len()),
                "produced {produced} gave {cut:?}"
            );
        }
    }

    /// An empty content array is rejected by the API. Compaction must not *choose* a
    /// boundary it can see is invalid, even one a caller put there.
    #[test]
    fn a_cut_onto_an_empty_content_array_is_refused() {
        let history = vec![
            user_text("one"),
            user_text("two"),
            empty_user(),
            user_text("four"),
        ];

        // The target is 2, which is the empty message; 3 is the next legal boundary.
        assert_eq!(plan_cut(&history, 0, Some(2), 0), Some(3));
    }

    /// The predicate is "contains no `ToolResult`", not "is not solely a `ToolResult`".
    /// `run_turn` never builds this shape; a caller assembling its own history can, and
    /// cutting onto it orphans the `tool_use` in the message before.
    #[test]
    fn a_user_message_mixing_prose_and_a_tool_result_is_not_a_boundary() {
        let mixed = RequestMessage {
            role: Role::User,
            content: vec![
                ContentBlock::ToolResult {
                    tool_use_id: "a".to_string(),
                    content: "ok".to_string(),
                    is_error: None,
                },
                ContentBlock::Text {
                    text: "and another thing".to_string(),
                },
            ],
        };
        let history = vec![
            user_text("one"),
            assistant_call("a"),
            mixed,
            user_text("four"),
        ];

        assert_eq!(plan_cut(&history, 0, Some(2), 0), Some(3));
    }

    /// All the weight is in the turn's own output, which compaction cannot touch. The
    /// answer is `None` rather than a panic on an empty range.
    #[test]
    fn an_empty_history_is_left_uncompacted() {
        assert_eq!(plan_cut(&[], 0, Some(0), 0), None);
        assert_eq!(plan_cut(&[], 6, Some(2), 0), None);
    }

    /// Monotonicity, which is what lets `run_turn` freeze the cut for the whole turn: a
    /// larger conversation never proposes a shallower cut. If it could, the request's
    /// cached prefix would be rebuilt backwards as the turn went round again.
    #[test]
    fn a_growing_conversation_never_proposes_a_shallower_cut() {
        let mut history = exchange("a", "first");
        history.extend(exchange("b", "second"));
        history.extend(exchange("c", "third"));

        let mut deepest = 0;
        for produced in 0..8 {
            if let Some(cut) = plan_cut(&history, produced, Some(3), 0) {
                assert!(cut >= deepest, "produced {produced} went back to {cut}");
                deepest = cut;
            }
        }
    }

    /// The fix for the oscillation that made the first version of this bound nothing.
    /// The figure a caller measures after a compaction is the cost of the *compacted*
    /// request, so the next turn reads under budget — and without a floor it would put
    /// the whole, now-longer history back and send more than the turn that triggered.
    #[test]
    fn a_turn_within_budget_still_holds_what_the_previous_turn_withheld() {
        let mut history = exchange("a", "first");
        history.extend(exchange("b", "second"));
        history.extend(exchange("c", "third"));

        // `None` is the within-budget case: nothing asks to deepen, so the floor is the
        // whole answer.
        assert_eq!(plan_cut(&history, 0, None, 4), Some(4));
    }

    /// The same floor, now with a `keep_recent` that on its own would cut shallower.
    /// Honouring it would undo a cut the previous turn already paid for and re-show the
    /// model history it had lost.
    #[test]
    fn a_keep_recent_that_asks_for_a_shallower_cut_than_the_floor_is_overruled() {
        let mut history = exchange("a", "first");
        history.extend(exchange("b", "second"));
        history.extend(exchange("c", "third"));

        // 12 messages, keep 10 ⇒ target 2 on its own. The floor wins.
        assert_eq!(history.len(), 12);
        assert_eq!(plan_cut(&history, 0, Some(10), 0), Some(4));
        assert_eq!(plan_cut(&history, 0, Some(10), 8), Some(8));
    }

    /// The floor is a floor, not a ceiling: a conversation that has grown back over
    /// budget since the last cut has to be cut deeper, or it is bounded only once.
    #[test]
    fn a_floor_does_not_stop_the_cut_from_deepening() {
        let mut history = exchange("a", "first");
        history.extend(exchange("b", "second"));
        history.extend(exchange("c", "third"));

        assert_eq!(plan_cut(&history, 0, Some(3), 4), Some(8));
    }

    /// The floor is snapped forward to a legal boundary, never honoured literally. A
    /// cut carried in from a turn whose history has since been *appended* to is still
    /// legal, but this also covers the index landing mid-exchange.
    #[test]
    fn a_floor_that_is_not_itself_a_legal_boundary_is_snapped_forward() {
        let mut history = exchange("a", "first");
        history.extend(exchange("b", "second"));

        // Index 5 is an assistant turn and 6 a tool result; 4 is the prose boundary, so
        // a floor of 5 can only be met by the next one up — of which there is none, and
        // the request goes out whole rather than invalid.
        assert_eq!(plan_cut(&history, 0, None, 4), Some(4));
        assert_eq!(plan_cut(&history, 0, None, 5), None);
    }

    /// A floor past the end of the history it is meant to index — a caller that
    /// rewrote history rather than appending to it. Clamping rather than slicing is what
    /// keeps this a declined compaction instead of a panic in `run_turn`.
    #[test]
    fn a_floor_beyond_the_history_is_clamped_rather_than_indexed() {
        let history = exchange("a", "first");

        assert_eq!(plan_cut(&history, 0, None, 99), None);
        assert_eq!(plan_cut(&[], 0, None, 99), None);
    }

    /// With compaction on but never yet triggered there is no floor and nothing to
    /// hold, and the within-budget path must not invent a cut.
    #[test]
    fn a_turn_within_budget_with_no_floor_withholds_nothing() {
        let mut history = exchange("a", "first");
        history.extend(exchange("b", "second"));

        assert_eq!(plan_cut(&history, 0, None, 0), None);
    }

    /// A turn's first round has no measurement, and guessing would compact a
    /// conversation that may be two messages long. Only the round: `run_turn` feeds each
    /// round's own report back in, so this does not keep a whole turn uncompacted.
    #[test]
    fn over_budget_is_false_when_nothing_has_been_observed() {
        assert!(!over_budget(None, 0));
        assert!(!over_budget(None, 100));
    }

    /// Cache reads are real prompt tokens charged against the window. Counting only
    /// `input_tokens` would under-read a cached conversation by an order of magnitude —
    /// which is exactly the long conversation compaction exists for.
    #[test]
    fn over_budget_sums_the_three_prompt_counters() {
        let spread = usage(Some(40), Some(40), Some(40));

        assert_eq!(spread.prompt_tokens(), 120);
        assert!(over_budget(Some(spread), 119));
        assert!(!over_budget(Some(spread), 120), "the budget is a ceiling");
    }

    /// `output_tokens` is not on `PromptUsage` at all. Pinned behaviourally so a later
    /// field addition cannot quietly fold the reply into the prompt figure.
    #[test]
    fn the_prompt_figure_counts_only_the_request() {
        assert_eq!(usage(Some(10), None, None).prompt_tokens(), 10);
    }

    /// The API omits the cache fields entirely when no cache was involved. Treating a
    /// missing field as "unknown" and declining to compare would disable compaction for
    /// every uncached request.
    #[test]
    fn over_budget_treats_an_unreported_counter_as_zero() {
        assert_eq!(usage(Some(10), None, None).prompt_tokens(), 10);
        assert_eq!(usage(None, None, None).prompt_tokens(), 0);
        assert!(!over_budget(Some(usage(None, None, None)), 0));
    }

    /// Three saturated counters overflow a `u32`, which panics in a debug build. The
    /// figures come off the wire, so a hostile or simply broken response must not be
    /// able to take the turn down.
    #[test]
    fn over_budget_does_not_overflow_on_three_saturated_counters() {
        let saturated = usage(Some(u32::MAX), Some(u32::MAX), Some(u32::MAX));

        assert_eq!(saturated.prompt_tokens(), 3 * u64::from(u32::MAX));
        assert!(over_budget(Some(saturated), u32::MAX));
    }
}
