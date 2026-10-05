//! Public contract of [`run_turn`]: what one streamed turn becomes.
//!
//! Every test drives the loop through the closure seam `run_turn` is generic over, with
//! the local [`Script`] on the other side, so the suite runs with no network access and
//! no API key. Assertions go through `serde_json::to_value` because `ContentBlock` is
//! `Serialize`-only with no `PartialEq` — against `TurnOutcome::messages` for the turn's
//! own output, and against `Script::sent` for what the API would have received, which is
//! what compaction changes.

use std::collections::VecDeque;

use sandbx_agent::{Compaction, PromptUsage, Turn, TurnError, TurnLimits, run_turn};
use sandbx_core::SandboxPolicy;
use sandbx_providers::{
    AgentEvent, EventStream, MessagesRequest, ProviderError, RequestMessage, Role, StopReason,
};
use sandbx_tools::{BuiltinTool, ExecutionContext};

/// Scripts one canned round per call, and records what was sent.
///
/// Not built on `sandbx-providers`' `MockProvider`: borrowing the one line it would
/// save costs a `mock` feature, a `required-features` test target and a CI command
/// naming both, and the recording has to live here anyway since it discards its own.
struct Script {
    rounds: VecDeque<Vec<AgentEvent>>,
    sent: Vec<MessagesRequest>,
}

impl Script {
    fn new(rounds: impl IntoIterator<Item = Vec<AgentEvent>>) -> Self {
        Self {
            rounds: rounds.into_iter().collect(),
            sent: Vec::new(),
        }
    }

    async fn open(&mut self, request: MessagesRequest) -> Result<EventStream, ProviderError> {
        self.sent.push(request.clone());
        // Not `unwrap_or_default`: an empty round surfaces as
        // `StreamEndedWithoutStop`, so a miscounted script would fail with a
        // misleading cause instead of naming itself.
        let events = self
            .rounds
            .pop_front()
            .expect("the script was asked for more rounds than it holds");
        Ok(canned(events))
    }
}

/// An `EventStream` that replays `events` and then ends.
///
/// `fuse()` because `EventStream` promises a `FusedStream`: a caller may poll it past
/// its end without panicking.
fn canned(events: Vec<AgentEvent>) -> EventStream {
    use futures_util::StreamExt;
    Box::pin(futures_util::stream::iter(events.into_iter().map(Ok)).fuse())
}

fn turn<'a>(history: &'a [RequestMessage], tools: &'a [BuiltinTool]) -> Turn<'a> {
    Turn {
        model: "claude-opus-5".to_string(),
        max_tokens: 1024,
        system: None,
        tools,
        history,
        limits: TurnLimits::default(),
        observed: None,
        withheld: 0,
    }
}

fn ctx(policy: SandboxPolicy) -> ExecutionContext {
    ExecutionContext::new(policy)
}

fn text(delta: &str) -> AgentEvent {
    AgentEvent::Text {
        delta: delta.to_string(),
    }
}

fn stop(reason: StopReason) -> AgentEvent {
    AgentEvent::Stop { reason }
}

/// The id every scripted call uses; each round here makes exactly one call.
const CALL_ID: &str = "call_1";

fn call(name: &str, input: serde_json::Value) -> AgentEvent {
    AgentEvent::ToolCallRequested {
        id: CALL_ID.to_string(),
        name: name.to_string(),
        input,
    }
}

/// The rebuilt history in the only form `ContentBlock` can be compared in.
fn wire(messages: &[RequestMessage]) -> serde_json::Value {
    serde_json::to_value(messages).unwrap()
}

/// The single `tool_result` block a scripted call produced.
fn tool_error(messages: &[RequestMessage]) -> serde_json::Value {
    wire(messages)[1]["content"][0].clone()
}

#[tokio::test]
async fn text_deltas_accumulate_into_one_block() {
    let mut script = Script::new([vec![text("Hel"), text("lo"), stop(StopReason::EndTurn)]]);

    let messages = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[]),
        &ctx(SandboxPolicy::default()),
        |_| {},
    )
    .await
    .unwrap()
    .messages;

    assert_eq!(
        wire(&messages),
        serde_json::json!([
            { "role": "assistant", "content": [{ "type": "text", "text": "Hello" }] }
        ])
    );
}

/// `sandbx-providers` discards the signature Anthropic streams alongside a thinking
/// block, so it cannot be replayed into a later request — but a TUI still has to see
/// it to render extended thinking.
#[tokio::test]
async fn thinking_reaches_the_observer_not_the_replay() {
    let thinking = AgentEvent::Thinking {
        delta: "weighing it up".to_string(),
    };
    let mut script = Script::new([vec![
        thinking.clone(),
        text("done"),
        stop(StopReason::EndTurn),
    ]]);
    let mut seen = Vec::new();

    let messages = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[]),
        &ctx(SandboxPolicy::default()),
        |event: &AgentEvent| seen.push(event.clone()),
    )
    .await
    .unwrap()
    .messages;

    assert_eq!(
        wire(&messages),
        serde_json::json!([
            { "role": "assistant", "content": [{ "type": "text", "text": "done" }] }
        ])
    );
    assert!(seen.contains(&thinking), "got {seen:?}");
}

/// Text arrives as increments, never as the accumulated total, so a renderer needs
/// each event as it lands rather than only the finished block.
#[tokio::test]
async fn the_observer_sees_every_event_in_arrival_order() {
    let round = vec![
        text("a"),
        text("b"),
        AgentEvent::Usage {
            input_tokens: Some(3),
            output_tokens: Some(4),
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        stop(StopReason::EndTurn),
    ];
    let mut script = Script::new([round.clone()]);
    let mut seen = Vec::new();

    run_turn(
        async |r| script.open(r).await,
        turn(&[], &[]),
        &ctx(SandboxPolicy::default()),
        |event: &AgentEvent| seen.push(event.clone()),
    )
    .await
    .unwrap();

    assert_eq!(seen, round);
}

/// The API rejects a message whose content array is empty, so appending one would
/// poison every later request in the conversation.
#[tokio::test]
async fn a_round_that_produced_nothing_appends_no_message() {
    let mut script = Script::new([vec![stop(StopReason::EndTurn)]]);

    let messages = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[]),
        &ctx(SandboxPolicy::default()),
        |_| {},
    )
    .await
    .unwrap()
    .messages;

    assert!(messages.is_empty(), "got {:?}", wire(&messages));
}

/// A real provider ends a turn with `Stop` or with an `Err`, never with silence, so
/// treating a silent end as success hands back a turn nothing can tell from a
/// truncated one.
#[tokio::test]
async fn a_stream_that_never_reports_a_stop_is_an_error() {
    let mut script = Script::new([vec![text("cut off")]]);

    let error = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[]),
        &ctx(SandboxPolicy::default()),
        |_| {},
    )
    .await
    .expect_err("a stream with no Stop event must not succeed");

    assert!(
        matches!(error, TurnError::StreamEndedWithoutStop),
        "got {error:?}"
    );
}

#[tokio::test]
async fn a_definition_per_offered_tool_reaches_the_request() {
    let history = vec![RequestMessage {
        role: Role::User,
        content: vec![sandbx_providers::ContentBlock::Text {
            text: "hello".to_string(),
        }],
    }];
    let mut script = Script::new([vec![text("hi"), stop(StopReason::EndTurn)]]);

    run_turn(
        async |r| script.open(r).await,
        turn(&history, &[BuiltinTool::Read]),
        &ctx(SandboxPolicy::default()),
        |_| {},
    )
    .await
    .unwrap();

    let sent = serde_json::to_value(&script.sent[0]).unwrap();
    assert_eq!(sent["model"], "claude-opus-5");
    assert_eq!(sent["max_tokens"], 1024);
    assert_eq!(sent["messages"], wire(&history));
    assert_eq!(sent["tools"][0]["name"], BuiltinTool::Read.name());
    assert_eq!(
        sent["tools"][0]["description"],
        BuiltinTool::Read.description()
    );
    assert_eq!(
        sent["tools"][0]["input_schema"],
        BuiltinTool::Read.input_schema()
    );
}

/// The loop end to end: assistant text, a tool call running under a policy, its
/// result threaded back, and a second round that sees all of it.
#[tokio::test]
async fn a_tool_result_is_fed_into_the_next_round() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("note.txt");
    let input = serde_json::json!({ "path": file.to_str().unwrap(), "content": "written" });
    let ctx = ctx(SandboxPolicy::default().allow_write(root.path()));

    let mut script = Script::new([
        vec![
            text("Writing it now."),
            call("write", input.clone()),
            stop(StopReason::ToolUse),
        ],
        vec![text("Done."), stop(StopReason::EndTurn)],
    ]);

    let messages = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Write]),
        &ctx,
        |_| {},
    )
    .await
    .unwrap()
    .messages;

    assert_eq!(std::fs::read_to_string(&file).unwrap(), "written");

    assert_eq!(
        wire(&messages),
        serde_json::json!([
            {
                "role": "assistant",
                "content": [
                    { "type": "text", "text": "Writing it now." },
                    { "type": "tool_use", "id": "call_1", "name": "write", "input": input },
                ],
            },
            {
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": "call_1",
                    "content": format!("wrote 7 bytes to {}", file.display()),
                }],
            },
            { "role": "assistant", "content": [{ "type": "text", "text": "Done." }] },
        ])
    );

    // The second round has to carry the first one, or the model answers blind.
    let second = serde_json::to_value(&script.sent[1]).unwrap();
    assert_eq!(second["messages"], wire(&messages[..2]));
}

/// `message_delta.stop_reason` is nullable, so a round can reach `message_stop`
/// carrying tool calls *and* `StopReason::Unspecified`. Keying re-entry off the
/// reason rather than the calls would silently drop them.
#[tokio::test]
async fn a_tool_call_runs_without_a_stop_reason() {
    let root = tempfile::tempdir().unwrap();
    let ctx = ctx(SandboxPolicy::default().allow_read(root.path()));

    let mut script = Script::new([
        vec![
            call(
                "ls",
                serde_json::json!({ "path": root.path().to_str().unwrap() }),
            ),
            stop(StopReason::Unspecified),
        ],
        vec![text("listed"), stop(StopReason::EndTurn)],
    ]);

    let messages = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Ls]),
        &ctx,
        |_| {},
    )
    .await
    .unwrap()
    .messages;

    assert_eq!(messages.len(), 3, "got {:?}", wire(&messages));
    assert_eq!(script.sent.len(), 2, "the turn should have re-entered");
}

/// A refusal is not a turn-ending failure: the model is told, and gets to ask for
/// something in scope. The three `ToolError` variants only differ to the model if
/// they reach it; see `context/guide-tools.md`.
#[tokio::test]
async fn a_refused_tool_call_is_an_error_to_the_model() {
    let allowed = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let outside = elsewhere.path().join("escape.txt");
    let ctx = ctx(SandboxPolicy::default().allow_write(allowed.path()));

    let mut script = Script::new([
        vec![
            call(
                "write",
                serde_json::json!({ "path": outside.to_str().unwrap(), "content": "nope", }),
            ),
            stop(StopReason::ToolUse),
        ],
        vec![
            text("I will stay inside the root."),
            stop(StopReason::EndTurn),
        ],
    ]);

    let messages = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Write]),
        &ctx,
        |_| {},
    )
    .await
    .unwrap()
    .messages;

    assert!(!outside.exists(), "the write must not have happened");

    let result = tool_error(&messages);
    assert_eq!(result["is_error"], true);
    assert!(
        result["content"]
            .as_str()
            .unwrap()
            .contains("refused by the sandbox policy"),
        "got {result:?}"
    );
    assert_eq!(messages.len(), 3, "the turn should have carried on");
}

/// Arguments that do not match the schema are the model's mistake to fix, so the
/// turn does not end under it.
#[tokio::test]
async fn bad_tool_arguments_are_reported_as_an_error() {
    let root = tempfile::tempdir().unwrap();
    let ctx = ctx(SandboxPolicy::default().allow_write(root.path()));

    let mut script = Script::new([
        vec![
            // `content` is required, and absent.
            call(
                "write",
                serde_json::json!({ "path": root.path().join("x").to_str().unwrap() }),
            ),
            stop(StopReason::ToolUse),
        ],
        vec![text("Retrying properly."), stop(StopReason::EndTurn)],
    ]);

    let messages = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Write]),
        &ctx,
        |_| {},
    )
    .await
    .unwrap()
    .messages;

    let result = tool_error(&messages);
    assert_eq!(result["is_error"], true);
    assert!(
        result["content"]
            .as_str()
            .unwrap()
            .contains("invalid tool arguments"),
        "got {result:?}"
    );
}

/// `BuiltinTool::from_name` is exact-match on purpose, so a name that does not
/// resolve is a prompt or schema bug the model is the one to correct. Nothing runs.
#[tokio::test]
async fn an_unknown_tool_name_does_not_end_the_turn() {
    let mut script = Script::new([
        vec![call("rm", serde_json::json!({})), stop(StopReason::ToolUse)],
        vec![text("Using a real tool."), stop(StopReason::EndTurn)],
    ]);

    let messages = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Write]),
        &ctx(SandboxPolicy::default()),
        |_| {},
    )
    .await
    .unwrap()
    .messages;

    let result = tool_error(&messages);
    assert_eq!(result["is_error"], true);
    assert!(
        result["content"].as_str().unwrap().contains("rm"),
        "got {result:?}"
    );
    assert_eq!(messages.len(), 3, "the turn should have carried on");
}

/// A model that keeps asking for tools — looping on its own, or steered into it by
/// injected content — would otherwise drive tool execution without bound.
#[tokio::test]
async fn a_turn_ends_once_it_runs_out_of_rounds() {
    let root = tempfile::tempdir().unwrap();
    let ctx = ctx(SandboxPolicy::default().allow_read(root.path()));
    // Exactly as many rounds as the cap allows: an endless supply would hide the
    // dependency this test is about.
    let mut script = Script::new(std::iter::repeat_n(
        vec![
            call(
                "ls",
                serde_json::json!({ "path": root.path().to_str().unwrap() }),
            ),
            stop(StopReason::ToolUse),
        ],
        3,
    ));

    let mut asking_forever = turn(&[], &[BuiltinTool::Ls]);
    asking_forever.limits = TurnLimits {
        max_rounds: 3,
        ..TurnLimits::default()
    };

    let error = run_turn(async |r| script.open(r).await, asking_forever, &ctx, |_| {})
        .await
        .expect_err("a turn that never stops asking must not run forever");

    assert!(
        matches!(error, TurnError::RoundLimit { rounds: 3 }),
        "got {error:?}"
    );
    assert_eq!(
        script.sent.len(),
        3,
        "it should have asked exactly three times"
    );
}

/// Pinned literally rather than read off the type: the value is the claim.
#[test]
fn the_default_round_cap_is_the_documented_one() {
    assert_eq!(TurnLimits::default().max_rounds, 8);
}

/// A stream that opens and then goes quiet forever.
///
/// `stream::pending` satisfies the `FusedStream` `EventStream` promises: it never
/// yields and never claims to be terminated.
fn stalled() -> EventStream {
    Box::pin(futures_util::stream::pending())
}

/// A server that keeps the connection warm while producing nothing useful would
/// otherwise hold a turn open indefinitely; see `TurnLimits::stream_timeout` for why
/// the provider's own read timeout does not cover it. Paused time, so the runtime
/// auto-advances instead of this waiting out the bound.
#[tokio::test(start_paused = true)]
async fn a_round_that_never_finishes_streaming_times_out() {
    let mut stalling = turn(&[], &[]);
    stalling.limits = TurnLimits {
        stream_timeout: std::time::Duration::from_secs(30),
        ..TurnLimits::default()
    };

    let error = run_turn(
        async |_| Ok(stalled()),
        stalling,
        &ctx(SandboxPolicy::default()),
        |_| {},
    )
    .await
    .expect_err("a stream that never finishes must not hold the turn open");

    assert!(
        matches!(error, TurnError::TimedOut { after } if after == std::time::Duration::from_secs(30)),
        "got {error:?}"
    );
}

/// Pinned literally, like the round cap. It bounds one round's whole generation,
/// which is tighter than the 120s *per-chunk* read timeout underneath it and does not
/// replace it.
#[test]
fn the_default_stream_bound_is_the_documented_one() {
    assert_eq!(
        TurnLimits::default().stream_timeout,
        std::time::Duration::from_secs(300)
    );
}

/// The call shape `run_turn`'s docs promise, compiled but never run: a real
/// `AnthropicClient` borrowed by a plain non-async closure, which `AsyncFnMut` accepts
/// through the blanket impl for `FnMut(..) -> Future`. Also pins that the returned
/// future is `Send` — the one thing giving up a named `Fut` parameter could have cost.
#[allow(dead_code)]
fn documented_call_shape_stays_spawnable(
    client: &'static sandbx_providers::AnthropicClient,
    ctx: &'static ExecutionContext,
) {
    fn assert_send<T: Send>(_: T) {}

    assert_send(run_turn(
        |request| client.stream_chat(request),
        turn(&[], &[]),
        ctx,
        |_| {},
    ));
}

/// A round that produces nothing *after* tools have run is not a finished turn: the
/// transcript ends in a `tool_result` the model never answered, and handing that back as
/// success breaks the *next* request, where the caller's own user message makes two
/// consecutive user turns.
#[tokio::test]
async fn an_empty_round_mid_tool_use_is_an_error() {
    let root = tempfile::tempdir().unwrap();
    let ctx = ctx(SandboxPolicy::default().allow_read(root.path()));
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

    let error = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Ls]),
        &ctx,
        |_| {},
    )
    .await
    .expect_err("a transcript ending in an unanswered tool_result is not a turn");

    assert!(matches!(error, TurnError::EndedMidToolUse), "got {error:?}");
}

// ---------------------------------------------------------------------------------
// Compaction. The planner's own algebra is unit-tested beside the private `plan_cut` in
// `src/compact.rs`; these cover the wiring — that the trigger reads a measurement, that
// the measurement gets out of the turn, and that what reaches the API is still a
// conversation it would accept.
// ---------------------------------------------------------------------------------

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
    )
    .await
    .expect_err("a compacted turn ending on an unanswered tool_result is not a turn");

    assert!(matches!(error, TurnError::EndedMidToolUse), "got {error:?}");
}
