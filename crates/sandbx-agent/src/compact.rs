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
mod tests {
    use super::*;

    /// A human prose turn: the only shape that is a legal cut point.
    fn user_text(text: &str) -> RequestMessage {
        RequestMessage {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: text.to_string(),
            }],
        }
    }

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

    /// The user turn answering a call, which is never a legal cut point.
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

    /// A shape `run_turn` never produces, but a caller editing its own history can.
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

    /// The shapes the sweeps run over: too short to cut, legal boundaries only, one
    /// exchange, a caller's own malformed message, and two exchanges.
    fn shapes() -> Vec<Vec<RequestMessage>> {
        let mut long = exchange("a", "first");
        long.extend(exchange("b", "second"));

        vec![
            vec![user_text("one")],
            vec![user_text("one"), user_text("two")],
            exchange("a", "first"),
            vec![empty_user(), user_text("two")],
            long,
        ]
    }

    fn usage(input: Option<u32>, read: Option<u32>, creation: Option<u32>) -> PromptUsage {
        PromptUsage {
            input_tokens: input,
            cache_read_input_tokens: read,
            cache_creation_input_tokens: creation,
        }
    }

    /// Pins the search *direction*: scanning backward from the target would keep more
    /// than `keep_recent` and fail to get under budget.
    #[test]
    fn cut_lands_on_first_user_message_from_target() {
        let history = vec![
            user_text("one"),
            user_text("two"),
            user_text("three"),
            user_text("four"),
        ];

        assert_eq!(plan_cut(&history, 0, Some(2), 0), Some(2));
    }

    /// An orphaned `tool_result` is a hard API rejection, and in a tool-heavy transcript
    /// most indices are one.
    #[test]
    fn cut_onto_a_tool_result_takes_the_next_boundary() {
        let mut history = exchange("a", "first");
        history.extend(exchange("b", "second"));

        // Index 2 is the `tool_result` answering `a`; the next legal boundary is the
        // prose turn that opens the second exchange.
        assert_eq!(plan_cut(&history, 0, Some(6), 0), Some(4));
    }

    /// A cut onto an assistant message strands its `tool_use` as well.
    #[test]
    fn a_cut_onto_an_assistant_message_is_refused() {
        let history = exchange("a", "first");

        // Indices 1 and 3 are assistant turns, 2 is a tool result: nothing is legal.
        assert_eq!(plan_cut(&history, 0, Some(1), 0), None);
    }

    /// Rung 2: no legal cut is deep enough, so shed less than asked rather than nothing.
    #[test]
    fn an_unbroken_tail_falls_back_to_an_earlier_cut() {
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

    /// Rung 3: declines rather than cutting anyway, erroring, or looping — an invalid
    /// request fails where an oversized one might not.
    #[test]
    fn a_history_with_only_a_first_boundary_is_left_whole() {
        let mut history = vec![user_text("first")];
        for id in ["a", "b", "c"] {
            history.push(assistant_call(id));
            history.push(user_result(id));
        }

        assert_eq!(plan_cut(&history, 0, Some(1), 0), None);
    }

    /// The target lands on 0, and without the guard on that the forward scan cuts at the
    /// first boundary it finds.
    #[test]
    fn keep_recent_past_the_history_withholds_nothing() {
        let history = vec![user_text("one"), user_text("two")];

        assert_eq!(plan_cut(&history, 0, Some(2), 0), None);
        assert_eq!(plan_cut(&history, 0, Some(99), 0), None);
        assert_eq!(plan_cut(&history, 1, Some(3), 0), None);
    }

    /// Defined behaviour rather than rejected at construction: `Compaction` has public
    /// fields and no constructor to validate in.
    #[test]
    fn keep_recent_of_zero_cuts_to_the_newest_boundary() {
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

    /// Swept over the shapes that could break it.
    #[test]
    fn no_plan_ever_withholds_the_whole_history() {
        for history in shapes() {
            for produced in 0..4 {
                for floor in [0, 1, 2, 3, 4, 5, 99] {
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

    /// Growing the turn's own output only deepens the cut into history, never reaches
    /// past it.
    #[test]
    fn the_current_turns_messages_are_never_candidates() {
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

    /// Compaction must not choose a boundary it can see is invalid, even one a caller put
    /// there.
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

    /// The predicate is "contains no `ToolResult`", not "is not solely a `ToolResult`":
    /// cutting onto a mixed message orphans the `tool_use` in the one before.
    #[test]
    fn prose_mixed_with_a_tool_result_is_not_a_boundary() {
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

    /// `None` rather than a panic on an empty range.
    #[test]
    fn an_empty_history_is_left_uncompacted() {
        assert_eq!(plan_cut(&[], 0, Some(0), 0), None);
        assert_eq!(plan_cut(&[], 6, Some(2), 0), None);
    }

    /// A single-message history is the shape a one-shot caller builds, and the scans stop
    /// short of `history.len()`, so there is no cut to find. Whatever a caller put in that
    /// message therefore reaches every request of the turn — which is what lets a system
    /// prompt and the first instruction be relied on rather than merely hoped for.
    #[test]
    fn a_lone_message_cannot_be_withheld() {
        let history = vec![user_text("the whole instruction")];

        for keep_recent in [None, Some(0), Some(1), Some(99)] {
            for floor in [0, 1, 99] {
                assert_eq!(
                    plan_cut(&history, 0, keep_recent, floor),
                    None,
                    "keep_recent={keep_recent:?} floor={floor}"
                );
                assert_eq!(
                    plan_cut(&history, 6, keep_recent, floor),
                    None,
                    "keep_recent={keep_recent:?} floor={floor}, with the turn's own messages"
                );
            }
        }
    }

    /// Monotonicity is what lets `run_turn` re-plan each measured round without ever
    /// re-showing the model history it had already withheld.
    #[test]
    fn a_growing_conversation_never_cuts_shallower() {
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

    /// The oscillation guard: the figure a caller measures after a compaction is the cost
    /// of the *compacted* request, so the next turn reads under budget and without a
    /// floor would put the whole, now-longer history back.
    #[test]
    fn a_turn_in_budget_holds_the_previous_cut() {
        let mut history = exchange("a", "first");
        history.extend(exchange("b", "second"));
        history.extend(exchange("c", "third"));

        // `None` is the within-budget case: nothing asks to deepen, so the floor is the
        // whole answer.
        assert_eq!(plan_cut(&history, 0, None, 4), Some(4));
    }

    /// Honouring it would undo a cut the previous turn paid for and re-show the model
    /// history it had lost.
    #[test]
    fn the_floor_overrules_a_shallower_keep_recent() {
        let mut history = exchange("a", "first");
        history.extend(exchange("b", "second"));
        history.extend(exchange("c", "third"));

        // 12 messages, keep 10 ⇒ target 2 on its own. The floor wins.
        assert_eq!(history.len(), 12);
        assert_eq!(plan_cut(&history, 0, Some(10), 0), Some(4));
        assert_eq!(plan_cut(&history, 0, Some(10), 8), Some(8));
    }

    /// A conversation that has grown back over budget since the last cut has to be cut
    /// deeper, or it is bounded only once.
    #[test]
    fn a_floor_does_not_stop_the_cut_from_deepening() {
        let mut history = exchange("a", "first");
        history.extend(exchange("b", "second"));
        history.extend(exchange("c", "third"));

        assert_eq!(plan_cut(&history, 0, Some(3), 4), Some(8));
    }

    /// A floor carried in from a history that was only appended to is legal already, and
    /// is held exactly rather than snapped anywhere.
    #[test]
    fn a_legal_floor_is_met_exactly() {
        let mut history = exchange("a", "first");
        history.extend(exchange("b", "second"));

        assert_eq!(plan_cut(&history, 0, None, 4), Some(4));
    }

    /// Forward is still preferred for a floor landing mid-exchange: 5 is an assistant
    /// turn, 6 a tool result, and 8 the next prose boundary.
    #[test]
    fn an_illegal_floor_snaps_to_the_boundary_above() {
        let mut history = exchange("a", "first");
        history.extend(exchange("b", "second"));
        history.extend(exchange("c", "third"));

        assert_eq!(plan_cut(&history, 0, None, 5), Some(8));
    }

    /// Dropping the floor instead would hand the caller `withheld: 0` and restart
    /// compaction from zero — the re-growth the floor exists to prevent.
    #[test]
    fn an_illegal_floor_falls_back_below_itself() {
        let mut history = exchange("a", "first");
        history.extend(exchange("b", "second"));

        // Nothing legal at or above 5, so the deepest below it: one boundary shallower
        // than asked rather than the whole history.
        assert_eq!(plan_cut(&history, 0, None, 5), Some(4));
    }

    /// A caller that rewrote history rather than appending to it. Dropped rather than
    /// met from below: meeting it would withhold all but the newest exchange, and the
    /// count it came from describes a history that no longer exists.
    #[test]
    fn a_floor_past_the_history_is_dropped() {
        let cuttable = vec![user_text("one"), user_text("two"), user_text("three")];

        assert_eq!(plan_cut(&cuttable, 0, None, 99), None);
        assert_eq!(
            plan_cut(&cuttable, 0, None, 3),
            None,
            "the end is past it too"
        );
        assert_eq!(plan_cut(&exchange("a", "first"), 0, None, 99), None);
        assert_eq!(plan_cut(&[], 0, None, 99), None);

        // Dropped, not disabling: an over-budget turn still compacts on `keep_recent`.
        assert_eq!(plan_cut(&cuttable, 0, Some(1), 99), Some(2));
    }

    /// An unmeetable floor pushes the target past every boundary, so what is left can be
    /// less than `keep_recent` asked to keep. The floor outranks it.
    #[test]
    fn an_unmeetable_floor_can_outshed_keep_recent() {
        let mut history = exchange("a", "first");
        history.extend(exchange("b", "second"));
        history.extend(exchange("c", "third"));

        // Keep 11 of 12 ⇒ target 1 on its own; the floor of 10 is a tool result, and the
        // deepest boundary below it is 8.
        assert_eq!(plan_cut(&history, 0, Some(11), 10), Some(8));
    }

    /// The postcondition `run_turn`'s monotonicity rests on: a plan it can hand to the
    /// API, whatever floor it was given.
    #[test]
    fn every_plan_opens_a_request() {
        for history in shapes() {
            for produced in 0..4 {
                for floor in [0, 1, 2, 3, 4, 5, 99] {
                    for keep_recent in [None, Some(0), Some(1), Some(2), Some(3)] {
                        if let Some(cut) = plan_cut(&history, produced, keep_recent, floor) {
                            assert!(
                                opens_a_request(&history, cut),
                                "cut {cut} of {history:?} at {keep_recent:?}/floor {floor}"
                            );
                        }
                    }
                }
            }
        }
    }

    /// The other half of the postcondition. An illegal floor is exempt — that is the one
    /// case the cut may land below it.
    #[test]
    fn a_plan_is_never_shallower_than_a_legal_floor() {
        for history in shapes() {
            for produced in 0..4 {
                for floor in 0..6 {
                    if floor != 0 && !opens_a_request(&history, floor) {
                        continue;
                    }
                    for keep_recent in [None, Some(0), Some(1), Some(2), Some(3)] {
                        if let Some(cut) = plan_cut(&history, produced, keep_recent, floor) {
                            assert!(
                                cut >= floor,
                                "cut {cut} under floor {floor} of {history:?} at {keep_recent:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    /// Compaction on but never yet triggered: no floor, nothing to hold, and the
    /// within-budget path must not invent a cut.
    #[test]
    fn a_turn_in_budget_with_no_floor_withholds_nothing() {
        let mut history = exchange("a", "first");
        history.extend(exchange("b", "second"));

        assert_eq!(plan_cut(&history, 0, None, 0), None);
    }

    /// Guessing would compact a conversation that may be two messages long. Only the
    /// round, not the turn: `run_turn` feeds each round's own report back in.
    #[test]
    fn over_budget_is_false_before_any_observation() {
        assert!(!over_budget(None, 0));
        assert!(!over_budget(None, 100));
    }

    /// A cache read is a real prompt token charged against the window, so `input_tokens`
    /// alone would under-read a cached conversation by an order of magnitude.
    #[test]
    fn over_budget_sums_the_three_prompt_counters() {
        let spread = usage(Some(40), Some(40), Some(40));

        assert_eq!(spread.prompt_tokens(), 120);
        assert!(over_budget(Some(spread), 119));
        assert!(!over_budget(Some(spread), 120), "the budget is a ceiling");
    }

    /// Pinned behaviourally so a later field addition cannot fold the reply into the
    /// prompt figure.
    #[test]
    fn the_prompt_figure_counts_only_the_request() {
        assert_eq!(usage(Some(10), None, None).prompt_tokens(), 10);
    }

    /// The API omits the cache fields entirely when no cache was involved, so treating a
    /// missing field as "unknown" would disable compaction for every uncached request.
    #[test]
    fn over_budget_treats_an_unreported_counter_as_zero() {
        assert_eq!(usage(Some(10), None, None).prompt_tokens(), 10);
        assert_eq!(usage(None, None, None).prompt_tokens(), 0);
        assert!(!over_budget(Some(usage(None, None, None)), 0));
    }

    /// Three saturated counters overflow a `u32`, which panics in a debug build, and
    /// these figures come off the wire.
    #[test]
    fn over_budget_never_overflows_saturated_counters() {
        let saturated = usage(Some(u32::MAX), Some(u32::MAX), Some(u32::MAX));

        assert_eq!(saturated.prompt_tokens(), 3 * u64::from(u32::MAX));
        assert!(over_budget(Some(saturated), u32::MAX));
    }
}
