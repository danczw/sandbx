//! Compaction's wiring: that the trigger reads a measurement, that the measurement gets
//! out of the turn, and that what reaches the API is a conversation it would accept.
//!
//! The planner's own algebra is unit-tested beside the private `plan_cut`, in
//! `src/compact/tests.rs`. What is asserted here is `Script::sent` — the request itself.

use sandbx_agent::{Compaction, PromptUsage, TurnError, TurnLimits, run_turn};
use sandbx_core::SandboxPolicy;
use sandbx_providers::{AgentEvent, RequestMessage, Role, StopReason};
use sandbx_tools::BuiltinTool;

mod support;

use support::{Script, allow_all, call, ctx, stop, text, turn, wire};

/// A measurement large enough to put any test over the budgets used below.
fn measured(input: u32) -> AgentEvent {
    AgentEvent::Usage {
        input_tokens: Some(input),
        output_tokens: Some(1),
        cache_creation_input_tokens: None,
        cache_read_input_tokens: None,
    }
}

/// One prose turn, the shape that is a legal cut point.
fn said(text: &str) -> RequestMessage {
    RequestMessage {
        role: Role::User,
        content: vec![sandbx_providers::ContentBlock::Text {
            text: text.to_string(),
        }],
    }
}

/// An assistant turn, which is not one.
fn replied(text: &str) -> RequestMessage {
    RequestMessage {
        role: Role::Assistant,
        content: vec![sandbx_providers::ContentBlock::Text {
            text: text.to_string(),
        }],
    }
}

/// A four-message history whose only legal cut point is index 2.
fn conversation() -> Vec<RequestMessage> {
    vec![said("one"), replied("two"), said("three"), replied("four")]
}

/// An eight-message history, legal at every even index.
fn long_conversation() -> Vec<RequestMessage> {
    let mut history = conversation();
    history.extend([
        said("five"),
        replied("six"),
        said("seven"),
        replied("eight"),
    ]);
    history
}

/// A five-message history carrying a tool exchange, so only 0 and 3 are legal.
fn tool_chain() -> Vec<RequestMessage> {
    vec![
        said("first"),
        RequestMessage {
            role: Role::Assistant,
            content: vec![sandbx_providers::ContentBlock::ToolUse {
                id: "a".to_string(),
                name: "ls".to_string(),
                input: serde_json::json!({}),
            }],
        },
        RequestMessage {
            role: Role::User,
            content: vec![sandbx_providers::ContentBlock::ToolResult {
                tool_use_id: "a".to_string(),
                content: "ok".to_string(),
                is_error: None,
            }],
        },
        said("second"),
        replied("third"),
    ]
}

/// What the request at `round` carried as its messages.
fn sent(script: &Script, round: usize) -> serde_json::Value {
    serde_json::to_value(&script.sent[round]).unwrap()["messages"].clone()
}

/// Pinned literally rather than read off the type, because the value is the claim: on by
/// default would silently send a model less than it was given, against a context window
/// this crate cannot know.
#[test]
fn the_default_limits_leave_compaction_off() {
    assert!(TurnLimits::default().compaction.is_none());
}

/// The feedback loop the whole feature hangs on: without the counts leaving the turn
/// there is nothing for a policy to read.
#[tokio::test]
async fn the_outcome_carries_the_last_reported_usage() {
    let mut script = Script::new([vec![text("hi"), measured(4_000), stop(StopReason::EndTurn)]]);

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[]),
        &ctx(SandboxPolicy::default()),
        |_| {},
        allow_all,
    )
    .await
    .unwrap();

    assert_eq!(
        outcome.usage,
        Some(PromptUsage {
            input_tokens: Some(4_000),
            cache_read_input_tokens: None,
            cache_creation_input_tokens: None,
        }),
        "got {:?}",
        outcome.usage
    );
    assert_eq!(outcome.usage.unwrap().prompt_tokens(), 4_000);
}

/// `None` has to stay distinguishable from a reported zero, or a caller cannot tell
/// whether to keep the figure it already had or believe a new one.
#[tokio::test]
async fn a_round_with_no_usage_leaves_the_outcome_empty() {
    let mut script = Script::new([vec![text("hi"), stop(StopReason::EndTurn)]]);

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[]),
        &ctx(SandboxPolicy::default()),
        |_| {},
        allow_all,
    )
    .await
    .unwrap();

    assert!(outcome.usage.is_none(), "got {:?}", outcome.usage);
    assert_eq!(outcome.withheld, 0);
}

/// Guessing would compact a conversation that may be two messages long. Only the first
/// round: see [`a_first_turn_compacts_after_it_measures_itself`].
#[tokio::test]
async fn compaction_cannot_fire_on_a_turns_first_round() {
    let history = conversation();
    let mut script = Script::new([vec![text("hi"), stop(StopReason::EndTurn)]]);
    let mut turn = turn(&history, &[]);
    turn.limits.compaction = Some(Compaction {
        budget_tokens: 0,
        keep_recent: 1,
    });
    turn.observed = None;

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn,
        &ctx(SandboxPolicy::default()),
        |_| {},
        allow_all,
    )
    .await
    .unwrap();

    assert_eq!(sent(&script, 0), wire(&history));
    assert_eq!(outcome.withheld, 0);
}

/// Nothing threaded in: the turn measures itself on round one and acts on round two,
/// the only in-turn bound there is, since `produced` grows the request as the turn goes
/// round. Without it a turn whose tool results balloon the request re-sends it for all
/// eight rounds.
#[tokio::test]
async fn a_first_turn_compacts_after_it_measures_itself() {
    let history = conversation();
    let mut script = Script::new([
        vec![
            call("rm", serde_json::json!({})),
            measured(500),
            stop(StopReason::ToolUse),
        ],
        vec![text("done"), stop(StopReason::EndTurn)],
    ]);
    let mut turn = turn(&history, &[BuiltinTool::Write]);
    turn.limits.compaction = Some(Compaction {
        budget_tokens: 100,
        keep_recent: 2,
    });
    // Nothing carried in at all: a conversation's very first turn.
    turn.observed = None;
    turn.withheld = 0;

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn,
        &ctx(SandboxPolicy::default()),
        |_| {},
        allow_all,
    )
    .await
    .unwrap();

    // Round one goes out whole — there was no figure to go on yet.
    assert_eq!(sent(&script, 0), wire(&history));
    // Round two acts on round one's own 500, which is over the budget of 100.
    assert_eq!(outcome.withheld, 2, "got {:?}", sent(&script, 1));
    let second = sent(&script, 1);
    let kept = second.as_array().unwrap();
    assert_eq!(kept.len(), 4, "got {second:?}");
    assert_eq!(&kept[..2], &wire(&history[2..]).as_array().unwrap()[..]);
}

/// Without this, compaction is unconditional truncation wearing a budget.
#[tokio::test]
async fn a_turn_under_budget_sends_the_whole_history() {
    let history = conversation();
    let mut script = Script::new([vec![text("hi"), stop(StopReason::EndTurn)]]);
    let mut turn = turn(&history, &[]);
    turn.limits.compaction = Some(Compaction {
        budget_tokens: 10_000,
        keep_recent: 1,
    });
    turn.observed = Some(PromptUsage {
        input_tokens: Some(9_999),
        cache_read_input_tokens: None,
        cache_creation_input_tokens: None,
    });

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn,
        &ctx(SandboxPolicy::default()),
        |_| {},
        allow_all,
    )
    .await
    .unwrap();

    assert_eq!(sent(&script, 0), wire(&history));
    assert_eq!(outcome.withheld, 0);
}

/// The feature end to end. Asserted on what the script received rather than the return
/// value: the request is the only thing the API can reject.
#[tokio::test]
async fn a_turn_over_budget_sends_only_the_recent_messages() {
    let history = conversation();
    let mut script = Script::new([vec![text("hi"), stop(StopReason::EndTurn)]]);
    let mut turn = turn(&history, &[]);
    turn.limits.compaction = Some(Compaction {
        budget_tokens: 100,
        keep_recent: 2,
    });
    turn.observed = Some(PromptUsage {
        input_tokens: Some(101),
        cache_read_input_tokens: None,
        cache_creation_input_tokens: None,
    });

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn,
        &ctx(SandboxPolicy::default()),
        |_| {},
        allow_all,
    )
    .await
    .unwrap();

    assert_eq!(outcome.withheld, 2, "got {:?}", sent(&script, 0));
    assert_eq!(sent(&script, 0), wire(&history[2..]));
}

/// `outcome.usage` measures the request that was *already* compacted, so a caller
/// threading only that reads the next turn as under budget, puts the whole — now longer —
/// history back, and sends more than the turn that triggered. Two real turns, because the
/// failure lives entirely in the hand-off: either one in isolation looks correct.
#[tokio::test]
async fn the_turn_after_a_compaction_keeps_the_cut() {
    let policy = Compaction {
        budget_tokens: 100,
        keep_recent: 2,
    };

    let first_history = conversation();
    let mut first_script = Script::new([vec![text("hi"), measured(10), stop(StopReason::EndTurn)]]);
    let mut first = turn(&first_history, &[]);
    first.limits.compaction = Some(policy);
    first.observed = Some(PromptUsage {
        input_tokens: Some(101),
        cache_read_input_tokens: None,
        cache_creation_input_tokens: None,
    });

    let first_outcome = run_turn(
        async |r| first_script.open(r).await,
        first,
        &ctx(SandboxPolicy::default()),
        |_| {},
        allow_all,
    )
    .await
    .unwrap();

    assert_eq!(first_outcome.withheld, 2);
    assert_eq!(
        first_outcome.usage.map(|usage| usage.prompt_tokens()),
        Some(10),
        "the test needs the compacted request to measure back under budget"
    );

    // Exactly what a caller does between turns: append the turn it got, add the next
    // prompt, thread *both* halves of the feedback back.
    let mut second_history = first_history.clone();
    second_history.extend(first_outcome.messages.iter().cloned());
    second_history.push(said("five"));

    let mut second_script = Script::new([vec![text("ok"), stop(StopReason::EndTurn)]]);
    let mut second = turn(&second_history, &[]);
    second.limits.compaction = Some(policy);
    second.observed = first_outcome.usage;
    second.withheld = first_outcome.withheld;

    let second_outcome = run_turn(
        async |r| second_script.open(r).await,
        second,
        &ctx(SandboxPolicy::default()),
        |_| {},
        allow_all,
    )
    .await
    .unwrap();

    // Nothing asked to deepen — 10 is well under 100 — but the cut the first turn paid
    // for holds, and the longer history is still sent short.
    assert_eq!(
        second_outcome.withheld,
        2,
        "got {:?}",
        sent(&second_script, 0)
    );
    assert_eq!(sent(&second_script, 0), wire(&second_history[2..]));
}

/// A conversation that has grown back over budget since the last cut has to be cut
/// deeper, or it is bounded exactly once and then never again.
#[tokio::test]
async fn a_turn_still_over_budget_deepens_the_cut() {
    let history = long_conversation();
    let mut script = Script::new([vec![text("hi"), stop(StopReason::EndTurn)]]);
    let mut turn = turn(&history, &[]);
    turn.limits.compaction = Some(Compaction {
        budget_tokens: 100,
        keep_recent: 2,
    });
    turn.observed = Some(PromptUsage {
        input_tokens: Some(101),
        cache_read_input_tokens: None,
        cache_creation_input_tokens: None,
    });
    turn.withheld = 2;

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn,
        &ctx(SandboxPolicy::default()),
        |_| {},
        allow_all,
    )
    .await
    .unwrap();

    assert_eq!(outcome.withheld, 6, "got {:?}", sent(&script, 0));
    assert_eq!(sent(&script, 0), wire(&history[6..]));
}

/// Every turn after a successful compaction carries a floor, so a floor that froze the
/// cut would leave the in-turn bound working only for the one case that does not need it.
#[tokio::test]
async fn a_carried_floor_deepens_on_the_turns_own_figure() {
    let history = long_conversation();
    let mut script = Script::new([
        vec![
            call("rm", serde_json::json!({})),
            measured(500),
            stop(StopReason::ToolUse),
        ],
        vec![text("done"), stop(StopReason::EndTurn)],
    ]);
    let mut turn = turn(&history, &[BuiltinTool::Write]);
    turn.limits.compaction = Some(Compaction {
        budget_tokens: 100,
        keep_recent: 2,
    });
    // The steady state after a compaction: a floor to hold, and no figure of this turn's
    // own yet, so round one is under budget and holds the floor exactly.
    turn.observed = None;
    turn.withheld = 2;

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn,
        &ctx(SandboxPolicy::default()),
        |_| {},
        allow_all,
    )
    .await
    .unwrap();

    assert_eq!(sent(&script, 0), wire(&history[2..]));
    // Round two acts on round one's own 500, over the budget of 100.
    assert_eq!(outcome.withheld, 6, "got {:?}", sent(&script, 1));
    let kept = sent(&script, 1);
    let kept = kept.as_array().unwrap();
    assert_eq!(&kept[..2], &wire(&history[6..]).as_array().unwrap()[..]);
}

/// A caller that rewrites history rather than appending to it carries back a count that
/// no longer names a boundary. Dropping the floor would hand it `withheld: 0` and restart
/// compaction from zero.
#[tokio::test]
async fn an_illegal_carried_floor_still_compacts() {
    let history = tool_chain();
    let mut script = Script::new([vec![text("hi"), stop(StopReason::EndTurn)]]);
    let mut turn = turn(&history, &[]);
    turn.limits.compaction = Some(Compaction {
        budget_tokens: 10_000,
        keep_recent: 1,
    });
    turn.observed = Some(PromptUsage {
        input_tokens: Some(1),
        cache_read_input_tokens: None,
        cache_creation_input_tokens: None,
    });
    // Index 4 is an assistant turn and nothing above it is legal, so the floor can only
    // be met from below: 3, one boundary shallower than asked.
    turn.withheld = 4;

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn,
        &ctx(SandboxPolicy::default()),
        |_| {},
        allow_all,
    )
    .await
    .unwrap();

    let messages = sent(&script, 0);
    assert_eq!(outcome.withheld, 3, "got {messages:?}");
    assert_eq!(messages, wire(&history[3..]));
    assert_eq!(
        messages[0]["content"][0]["type"], "text",
        "the request opened on an orphaned tool_result: {messages:?}"
    );
}

/// A count larger than the history it names, which only a caller rewriting history can
/// produce. The floor is dropped, not clamped onto the end: clamping would both withhold
/// all but the newest exchange and leave `run_turn` slicing past its own history.
#[tokio::test]
async fn a_floor_past_the_history_sends_it_whole() {
    let history = long_conversation();
    let mut script = Script::new([vec![text("hi"), stop(StopReason::EndTurn)]]);
    let mut turn = turn(&history, &[]);
    turn.limits.compaction = Some(Compaction {
        budget_tokens: 10_000,
        keep_recent: 2,
    });
    turn.observed = Some(PromptUsage {
        input_tokens: Some(1),
        cache_read_input_tokens: None,
        cache_creation_input_tokens: None,
    });
    turn.withheld = 99;

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn,
        &ctx(SandboxPolicy::default()),
        |_| {},
        allow_all,
    )
    .await
    .unwrap();

    assert_eq!(outcome.withheld, 0, "got {:?}", sent(&script, 0));
    assert_eq!(sent(&script, 0), wire(&history));
}

/// `Usage` is nullable on the wire. Deepening on a figure already acted on would shed
/// context the turn cannot get back, and the turn would do it once per round.
#[tokio::test]
async fn a_round_with_no_usage_leaves_the_cut_alone() {
    let history = long_conversation();
    let mut script = Script::new([
        vec![call("rm", serde_json::json!({})), stop(StopReason::ToolUse)],
        vec![text("done"), stop(StopReason::EndTurn)],
    ]);
    let mut turn = turn(&history, &[BuiltinTool::Write]);
    // `keep_recent: 6` is what makes the difference visible: the target tracks `produced`,
    // so a re-plan on round two would reach index 4.
    turn.limits.compaction = Some(Compaction {
        budget_tokens: 100,
        keep_recent: 6,
    });
    turn.observed = Some(PromptUsage {
        input_tokens: Some(101),
        cache_read_input_tokens: None,
        cache_creation_input_tokens: None,
    });

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn,
        &ctx(SandboxPolicy::default()),
        |_| {},
        allow_all,
    )
    .await
    .unwrap();

    assert_eq!(outcome.withheld, 2, "got {:?}", sent(&script, 1));
    let kept = sent(&script, 1);
    let kept = kept.as_array().unwrap();
    assert_eq!(&kept[..6], &wire(&history[2..]).as_array().unwrap()[..]);
}

/// The same setup, with round one reporting: the cut deepens rather than reversing, so
/// the model is never re-shown history it had lost.
#[tokio::test]
async fn a_cut_already_taken_is_never_undone() {
    let history = long_conversation();
    let mut script = Script::new([
        vec![
            call("rm", serde_json::json!({})),
            measured(500),
            stop(StopReason::ToolUse),
        ],
        vec![text("done"), stop(StopReason::EndTurn)],
    ]);
    let mut turn = turn(&history, &[BuiltinTool::Write]);
    turn.limits.compaction = Some(Compaction {
        budget_tokens: 100,
        keep_recent: 6,
    });
    turn.observed = Some(PromptUsage {
        input_tokens: Some(101),
        cache_read_input_tokens: None,
        cache_creation_input_tokens: None,
    });

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn,
        &ctx(SandboxPolicy::default()),
        |_| {},
        allow_all,
    )
    .await
    .unwrap();

    assert_eq!(sent(&script, 0), wire(&history[2..]));
    assert_eq!(outcome.withheld, 4, "got {:?}", sent(&script, 1));
    let kept = sent(&script, 1);
    let kept = kept.as_array().unwrap();
    assert_eq!(&kept[..4], &wire(&history[4..]).as_array().unwrap()[..]);
}

/// Compaction narrows the request, not `TurnOutcome::messages`: a caller appends those
/// to its stored history, so a loss there would be permanent and compound every turn.
#[tokio::test]
async fn compaction_never_shortens_the_transcript() {
    let history = conversation();
    let mut script = Script::new([vec![text("hi"), stop(StopReason::EndTurn)]]);
    let mut turn = turn(&history, &[]);
    turn.limits.compaction = Some(Compaction {
        budget_tokens: 0,
        keep_recent: 1,
    });
    turn.observed = Some(PromptUsage {
        input_tokens: Some(1),
        cache_read_input_tokens: None,
        cache_creation_input_tokens: None,
    });

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn,
        &ctx(SandboxPolicy::default()),
        |_| {},
        allow_all,
    )
    .await
    .unwrap();

    assert!(outcome.withheld > 0, "the test needs compaction to fire");
    assert_eq!(
        wire(&outcome.messages),
        serde_json::json!([
            { "role": "assistant", "content": [{ "type": "text", "text": "hi" }] },
        ])
    );
}

/// The API rejects a conversation that does not open on a user turn, and index 1 of this
/// history is the assistant's.
#[tokio::test]
async fn a_compacted_request_opens_with_a_user_message() {
    let history = conversation();
    let mut script = Script::new([vec![text("hi"), stop(StopReason::EndTurn)]]);
    let mut turn = turn(&history, &[]);
    turn.limits.compaction = Some(Compaction {
        budget_tokens: 0,
        keep_recent: 3,
    });
    turn.observed = Some(PromptUsage {
        input_tokens: Some(1),
        cache_read_input_tokens: None,
        cache_creation_input_tokens: None,
    });

    run_turn(
        async |r| script.open(r).await,
        turn,
        &ctx(SandboxPolicy::default()),
        |_| {},
        allow_all,
    )
    .await
    .unwrap();

    assert_eq!(
        sent(&script, 0)[0]["role"],
        "user",
        "got {:?}",
        sent(&script, 0)
    );
}

/// An orphaned `tool_result` — one whose `tool_use` was withheld — is rejected outright,
/// and in a tool-heavy transcript most indices are one.
#[tokio::test]
async fn compaction_keeps_a_tool_result_with_its_call() {
    let history = tool_chain();
    let mut script = Script::new([vec![text("hi"), stop(StopReason::EndTurn)]]);
    let mut turn = turn(&history, &[]);
    // `keep_recent: 3` targets index 2 — the tool result. It must walk on to 3.
    turn.limits.compaction = Some(Compaction {
        budget_tokens: 0,
        keep_recent: 3,
    });
    turn.observed = Some(PromptUsage {
        input_tokens: Some(1),
        cache_read_input_tokens: None,
        cache_creation_input_tokens: None,
    });

    run_turn(
        async |r| script.open(r).await,
        turn,
        &ctx(SandboxPolicy::default()),
        |_| {},
        allow_all,
    )
    .await
    .unwrap();

    let messages = sent(&script, 0);
    assert_eq!(messages, wire(&history[3..]), "got {messages:?}");
    assert_eq!(
        messages[0]["content"][0]["type"], "text",
        "the request opened on an orphaned tool_result: {messages:?}"
    );
}

/// Rung 3 of the fallback ladder: cutting anyway would turn a request that *might* be
/// too long into one the API is certain to reject.
#[tokio::test]
async fn an_unbreakable_history_is_sent_oversized() {
    let mut history = vec![said("only prose turn")];
    for id in ["a", "b", "c"] {
        history.push(RequestMessage {
            role: Role::Assistant,
            content: vec![sandbx_providers::ContentBlock::ToolUse {
                id: id.to_string(),
                name: "ls".to_string(),
                input: serde_json::json!({}),
            }],
        });
        history.push(RequestMessage {
            role: Role::User,
            content: vec![sandbx_providers::ContentBlock::ToolResult {
                tool_use_id: id.to_string(),
                content: "ok".to_string(),
                is_error: None,
            }],
        });
    }
    let mut script = Script::new([vec![text("hi"), stop(StopReason::EndTurn)]]);
    let mut turn = turn(&history, &[]);
    turn.limits.compaction = Some(Compaction {
        budget_tokens: 0,
        keep_recent: 1,
    });
    turn.observed = Some(PromptUsage {
        input_tokens: Some(1),
        cache_read_input_tokens: None,
        cache_creation_input_tokens: None,
    });

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn,
        &ctx(SandboxPolicy::default()),
        |_| {},
        allow_all,
    )
    .await
    .unwrap();

    assert_eq!(outcome.withheld, 0);
    assert_eq!(sent(&script, 0), wire(&history));
}

/// A cut survives the rounds that follow it: nothing re-sends history the model has
/// already been denied, however `produced` grows behind it.
#[tokio::test]
async fn a_cut_is_reused_by_every_later_round() {
    let root = tempfile::tempdir().unwrap();
    let history = conversation();
    let mut script = Script::new([
        vec![
            call(
                "ls",
                serde_json::json!({ "path": root.path().to_str().unwrap() }),
            ),
            stop(StopReason::ToolUse),
        ],
        vec![text("done"), stop(StopReason::EndTurn)],
    ]);
    let mut turn = turn(&history, &[BuiltinTool::Ls]);
    turn.limits.compaction = Some(Compaction {
        budget_tokens: 100,
        keep_recent: 2,
    });
    turn.observed = Some(PromptUsage {
        input_tokens: Some(101),
        cache_read_input_tokens: None,
        cache_creation_input_tokens: None,
    });

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn,
        &ctx(SandboxPolicy::default().allow_read(root.path())),
        |_| {},
        allow_all,
    )
    .await
    .unwrap();

    assert_eq!(outcome.withheld, 2);
    // Round two carries the same withheld prefix, with this turn's own work after it.
    assert_eq!(sent(&script, 0), wire(&history[2..]));
    assert_eq!(sent(&script, 1)[0], wire(&history[2..])[0]);
    assert_eq!(sent(&script, 1)[1], wire(&history[2..])[1]);
}

/// The oscillation case. Round one's own measurement comes back *under* budget, so
/// round two re-plans with nothing asking to deepen — and the cut it already took is its
/// floor, which is what stops it putting the dropped history back.
#[tokio::test]
async fn usage_back_under_budget_mid_turn_keeps_the_cut() {
    let root = tempfile::tempdir().unwrap();
    let history = conversation();
    let mut script = Script::new([
        vec![
            call(
                "ls",
                serde_json::json!({ "path": root.path().to_str().unwrap() }),
            ),
            // Comfortably under the budget the turn was triggered on.
            measured(1),
            stop(StopReason::ToolUse),
        ],
        vec![text("done"), stop(StopReason::EndTurn)],
    ]);
    let mut turn = turn(&history, &[BuiltinTool::Ls]);
    turn.limits.compaction = Some(Compaction {
        budget_tokens: 100,
        keep_recent: 2,
    });
    turn.observed = Some(PromptUsage {
        input_tokens: Some(101),
        cache_read_input_tokens: None,
        cache_creation_input_tokens: None,
    });

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn,
        &ctx(SandboxPolicy::default().allow_read(root.path())),
        |_| {},
        allow_all,
    )
    .await
    .unwrap();

    assert_eq!(outcome.withheld, 2);
    assert_eq!(sent(&script, 1)[0], wire(&history[2..])[0]);
    // And the turn still reports what it last measured, low as it was.
    assert_eq!(outcome.usage.unwrap().prompt_tokens(), 1);
}

/// `produced` is handed to the planner as a count, never a slice, so a `keep_recent`
/// smaller than this turn's own output cannot force that output out. Withholding the
/// tool result the model is waiting on would be API-valid and useless — the turn would
/// loop until it ran out of rounds.
#[tokio::test]
async fn a_keep_recent_under_the_turns_output_sends_it() {
    let root = tempfile::tempdir().unwrap();
    let history = conversation();
    let mut script = Script::new([
        vec![
            call(
                "ls",
                serde_json::json!({ "path": root.path().to_str().unwrap() }),
            ),
            stop(StopReason::ToolUse),
        ],
        vec![text("done"), stop(StopReason::EndTurn)],
    ]);
    let mut turn = turn(&history, &[BuiltinTool::Ls]);
    turn.limits.compaction = Some(Compaction {
        budget_tokens: 0,
        keep_recent: 1,
    });
    turn.observed = Some(PromptUsage {
        input_tokens: Some(1),
        cache_read_input_tokens: None,
        cache_creation_input_tokens: None,
    });

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn,
        &ctx(SandboxPolicy::default().allow_read(root.path())),
        |_| {},
        allow_all,
    )
    .await
    .unwrap();

    // Round two's request is built from the two messages round one produced — the call
    // and its result — whatever was withheld in front of them. They are the tail.
    let second = sent(&script, 1);
    let own = wire(&outcome.messages[..2]);
    let count = second.as_array().unwrap().len();
    assert!(count >= 2, "got {second:?}");
    assert_eq!(second[count - 2], own[0], "got {second:?}");
    assert_eq!(second[count - 1], own[1], "got {second:?}");
}

/// The degenerate configuration, given defined behaviour rather than rejected at
/// construction: `Compaction` has public fields and no constructor to validate in.
#[tokio::test]
async fn a_budget_of_zero_compacts_every_measured_turn() {
    let history = conversation();
    let mut script = Script::new([vec![text("hi"), stop(StopReason::EndTurn)]]);
    let mut turn = turn(&history, &[]);
    turn.limits.compaction = Some(Compaction {
        budget_tokens: 0,
        keep_recent: 2,
    });
    turn.observed = Some(PromptUsage {
        input_tokens: Some(1),
        cache_read_input_tokens: None,
        cache_creation_input_tokens: None,
    });

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn,
        &ctx(SandboxPolicy::default()),
        |_| {},
        allow_all,
    )
    .await
    .unwrap();

    assert_eq!(outcome.withheld, 2);
}

/// `EndedMidToolUse` reads `produced`, which compaction cannot reach, so the check is
/// unchanged with it on. The coupling runs the other way: withholding history is one of
/// the things that can confuse a model into an empty round.
#[tokio::test]
async fn a_compacted_turn_ending_mid_tool_use_is_an_error() {
    let root = tempfile::tempdir().unwrap();
    let history = conversation();
    let mut script = Script::new([
        vec![
            call(
                "ls",
                serde_json::json!({ "path": root.path().to_str().unwrap() }),
            ),
            stop(StopReason::ToolUse),
        ],
        // Answered the tool, then said nothing at all.
        vec![stop(StopReason::EndTurn)],
    ]);
    let mut turn = turn(&history, &[BuiltinTool::Ls]);
    turn.limits.compaction = Some(Compaction {
        budget_tokens: 0,
        keep_recent: 2,
    });
    turn.observed = Some(PromptUsage {
        input_tokens: Some(1),
        cache_read_input_tokens: None,
        cache_creation_input_tokens: None,
    });

    let error = run_turn(
        async |r| script.open(r).await,
        turn,
        &ctx(SandboxPolicy::default().allow_read(root.path())),
        |_| {},
        allow_all,
    )
    .await
    .expect_err("a compacted turn ending on an unanswered tool_result is not a turn");

    assert!(matches!(error, TurnError::EndedMidToolUse), "got {error:?}");
}
