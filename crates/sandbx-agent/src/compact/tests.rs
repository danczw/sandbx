//! Unit tests for the cut planner: which prefix of a history may be withheld, and
//! which boundaries are legal cut points.
//!
//! `tests/turn_compaction.rs` covers the wiring instead — that a measurement reaches
//! the trigger and that what reaches the API is a conversation it would accept.

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
