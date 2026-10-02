//! Public contract of [`run_turn`]: what one streamed turn becomes.
//!
//! Every test drives the loop through the closure seam `run_turn` is generic
//! over, with the local [`Script`] on the other side of it — deliberately not
//! `MockProvider`, for the reasons given there — so the whole suite runs with no
//! network access and no API key. Assertions on the rebuilt history go
//! through `serde_json::to_value`, because `ContentBlock` is `Serialize`-only and
//! has no `PartialEq` to compare against — on `TurnOutcome::messages` where the
//! turn's own output is what matters, and on `Script::sent` where the question is
//! what the API would have received, which is what compaction changes.

use std::collections::VecDeque;

use sandbx_agent::{Compaction, PromptUsage, Turn, TurnError, TurnLimits, run_turn};
use sandbx_core::SandboxPolicy;
use sandbx_providers::{
    AgentEvent, EventStream, MessagesRequest, ProviderError, RequestMessage, Role, StopReason,
};
use sandbx_tools::{BuiltinTool, ExecutionContext};

/// Scripts one canned round per call, and records what was sent.
///
/// This is the seam itself. `run_turn` asks for a closure that opens a stream, so a
/// test hands it one that pops a canned round off the front and replays it.
///
/// Deliberately not built on `sandbx-providers`' `MockProvider`: that double's whole
/// body is the `stream::iter(..).fuse()` in [`canned`] below, and reaching for it
/// would mean a `mock` feature here, a `required-features` test target, and a CI
/// command that has to name both — three coordinated parts, one of them a silent
/// failure if forgotten, to borrow one line. Recording the requests has to live here
/// either way, since `MockProvider` discards its own.
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
        // `StreamEndedWithoutStop`, so a test that miscounted rounds would fail with a
        // misleading cause instead of naming the script.
        let events = self
            .rounds
            .pop_front()
            .expect("the script was asked for more rounds than it holds");
        Ok(canned(events))
    }
}

/// An `EventStream` that replays `events` and then ends.
///
/// `fuse()` because `EventStream` promises a `FusedStream` — a caller may poll it
/// past its end without panicking.
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

/// Same shape the `sandbx-tools` suites use, so all eight call sites share it.
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

/// The id every scripted call uses. Each round in this suite makes exactly one call,
/// so threading a distinct id through every site would add noise and prove nothing.
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

/// The single `tool_result` block a scripted call produced. The asserts stay at each
/// call site so a failure still points at the test that cares.
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

/// `sandbx-providers` discards the cryptographic signature that Anthropic streams
/// alongside a thinking block, and `ContentBlock` has no thinking variant, so a
/// thinking block cannot be replayed into a later request. It still has to reach
/// the caller, or a TUI could not render extended thinking at all.
#[tokio::test]
async fn thinking_reaches_the_observer_but_not_the_replayed_turn() {
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

/// Text arrives as increments, never as the accumulated total, so a renderer
/// needs each event as it lands rather than only the finished block. Leaving that
/// to every consumer is the duplication #58 exists to stop.
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

/// The API rejects a message whose content array is empty, so a round that
/// produced nothing must append no message at all — appending an empty one would
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

/// A real provider ends a turn with `Stop` or with an `Err`, never with silence.
/// Treating a silent end as success would hand back a turn nothing can tell apart
/// from a truncated one.
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

/// The request is where the two crates either side of this one actually meet: the
/// history goes out verbatim, and each offered built-in has to arrive as the
/// `ToolDefinition` shape a provider wants, bridged from its own accessors.
#[tokio::test]
async fn the_request_carries_the_history_and_a_definition_per_offered_tool() {
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

/// The whole point of the loop, end to end: assistant text, a tool call, the tool
/// actually running under a policy, its result threaded back, and a second round
/// that sees all of it. No network and no API key anywhere in it.
#[tokio::test]
async fn a_tool_call_runs_and_its_result_is_fed_back_into_the_next_round() {
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
/// carrying tool calls *and* `StopReason::Unspecified`. Keying re-entry off the stop
/// reason instead of off the calls themselves would silently drop them.
#[tokio::test]
async fn a_tool_call_is_answered_even_when_no_stop_reason_was_reported() {
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

/// A refusal is not a turn-ending failure: the model is told it was refused and
/// gets to ask for something in scope. `context/guide-tools.md` is explicit that the
/// three `ToolError` variants exist because the model reacts to them differently,
/// which only works if they reach it.
#[tokio::test]
async fn a_refused_tool_call_is_reported_to_the_model_as_an_error() {
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

/// Arguments that do not match the schema are the model's mistake to fix, so it is
/// told what was wrong rather than having the turn end under it.
#[tokio::test]
async fn a_tool_call_with_bad_arguments_is_reported_as_an_error() {
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
/// resolve is a prompt or schema bug. The model is the one that can correct it, so
/// it is told — and nothing runs in the meantime.
#[tokio::test]
async fn an_unknown_tool_name_is_reported_rather_than_ending_the_turn() {
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
/// injected content — would otherwise drive tool execution without bound. The cap is
/// what makes a turn's total cost derivable instead of open-ended.
#[tokio::test]
async fn a_turn_ends_once_it_runs_out_of_rounds() {
    let root = tempfile::tempdir().unwrap();
    let ctx = ctx(SandboxPolicy::default().allow_read(root.path()));
    // Exactly as many rounds as the cap allows: `run_turn` can never ask for more, so
    // an endless supply would only hide the dependency this test is about.
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

/// Pinned literally rather than read off the type, because the value is the claim:
/// with no caller measured yet, the default is deliberately at the tighter end, so a
/// limit that is too low announces itself where one that is too high silently fails
/// to catch the runaway it exists for.
#[test]
fn the_default_round_cap_is_the_documented_one() {
    assert_eq!(TurnLimits::default().max_rounds, 8);
}

/// A stream that opens and then goes quiet forever.
///
/// `EventStream` is a `FusedStream`, which `stream::pending` satisfies — it never
/// yields and never claims to be terminated.
fn stalled() -> EventStream {
    Box::pin(futures_util::stream::pending())
}

/// A server that keeps the connection warm while producing nothing useful would
/// otherwise hold a turn open indefinitely — see `TurnLimits::stream_timeout` for why
/// the provider's own read timeout does not cover this.
///
/// Paused time rather than a real sleep: the runtime auto-advances once nothing else
/// can make progress, so this asserts the bound without waiting for it.
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

/// Pinned literally, like the round cap: the number is the claim. It bounds one
/// round's whole generation, which is strictly tighter than the 120s *per-chunk*
/// read timeout underneath it, and does not replace it.
#[test]
fn the_default_stream_bound_is_the_documented_one() {
    assert_eq!(
        TurnLimits::default().stream_timeout,
        std::time::Duration::from_secs(300)
    );
}

/// The call shape `run_turn`'s own docs promise, compiled but never run: a real
/// `AnthropicClient`, borrowed by a plain non-async closure. `AsyncFnMut` is
/// satisfied here by the blanket impl for `FnMut(..) -> Future`, so if that ever
/// stopped covering this shape the build would fail rather than leave the doc
/// comment lying.
///
/// The closure can stay non-async because `stream_chat` returns `EventStream`
/// directly, so there is nothing left here to box.
///
/// Also pins that the returned future is `Send` — the one thing giving up a named
/// `Fut` type parameter could have cost. See `sandbx-providers`' `EventStream` for
/// why that matters.
#[allow(dead_code)]
fn the_documented_call_shape_compiles_and_stays_spawnable(
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

/// A round that produces nothing *after* tools have run is not a finished turn.
///
/// `a_round_that_produced_nothing_appends_no_message` covers the other shape of
/// this: an empty first round, where there is nothing to hand back and `Ok` with
/// an empty transcript is right. Here the transcript ends in the `tool_result`
/// the model never answered, and handing that back as success breaks the *next*
/// request — the caller appends its own user message after it, and the API
/// rejects two consecutive user turns with `roles must alternate between "user"
/// and "assistant"`. Same treatment as `RoundLimit`, for the same reason.
#[tokio::test]
async fn a_turn_that_ends_on_an_empty_round_mid_tool_use_is_an_error() {
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
// Compaction (#107). The planner's own algebra is unit-tested in `src/compact.rs`,
// where `plan_cut` lives and is private; these cover the wiring — that the trigger is
// wired to a measurement, that the measurement gets out of the turn at all, and that
// what reaches the API is still a conversation it would accept.
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

/// What the request at `round` carried as its messages.
fn sent(script: &Script, round: usize) -> serde_json::Value {
    serde_json::to_value(&script.sent[round]).unwrap()["messages"].clone()
}

/// Pinned literally rather than read off the type, because the value is the claim.
///
/// Compaction is the one bound here that is lossy, and the only one whose right value
/// depends on the model named in the request. On by default would silently send a model
/// less than it was given, against a context window this crate cannot know.
#[test]
fn the_default_limits_leave_compaction_off() {
    assert!(TurnLimits::default().compaction.is_none());
}

/// The feedback loop the whole feature hangs on. This event used to be observed and
/// then dropped on the floor, so there was nothing for a policy to read.
#[tokio::test]
async fn the_outcome_carries_the_last_usage_the_round_reported() {
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
async fn a_round_that_reported_no_usage_leaves_the_outcome_usage_empty() {
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

/// A conversation's first turn has no measurement to go on for its *first round*, and
/// guessing would compact a conversation that may be two messages long.
///
/// Only the first round. A turn that measures itself over budget compacts from the next
/// round on, with no previous turn involved — see
/// [`a_first_turn_compacts_from_the_round_after_it_measures_itself`].
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

/// The other half of the above, and the reason that one says *round* rather than *turn*.
/// Nothing is threaded in here: the turn measures itself on round one and acts on it on
/// round two, which is the only in-turn bound there is — `produced` grows the request as
/// the turn goes round, and this is the single opportunity to react to it.
///
/// So the cut moves exactly once, `None` to `Some`, which narrows the request's cached
/// prefix mid-turn. Deliberate: the alternative is a turn that watches itself blow
/// through the budget and keeps sending the whole history for all eight rounds. Monotone
/// either way, so the model is never re-shown history it had lost — only
/// `usage_falling_back_under_budget_mid_turn_does_not_put_the_history_back` could break
/// that, and it does not.
#[tokio::test]
async fn a_first_turn_compacts_from_the_round_after_it_measures_itself() {
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

/// The trigger has to be a trigger. A history that fits is sent whole, or compaction is
/// just unconditional truncation wearing a budget.
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

/// The feature, end to end: a measurement fed in from the previous turn puts this one
/// over budget, and the request leaves the oldest exchange out.
///
/// Asserted on what the script received, not on the return value: the request is the
/// only thing the API can reject, so it is the only thing worth pinning here.
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

/// The regression for the thing that made the first version of this bound nothing at
/// all. `outcome.usage` measures the request that was *already* compacted, so a caller
/// threading only that reads the next turn as comfortably under budget, puts the whole —
/// now longer — history back, and sends more than the turn that triggered. Compaction
/// would fire on alternate turns while the uncompacted leg grew without limit.
///
/// Two real turns, threaded the way the docs prescribe, because the failure lives
/// entirely in the hand-off between them: one turn in isolation looks correct.
#[tokio::test]
async fn the_turn_after_a_compaction_does_not_put_the_history_back() {
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

/// The floor is a floor, not a ceiling. A conversation that has grown back over budget
/// since the last cut has to be cut deeper, or it is bounded exactly once and then never
/// again.
#[tokio::test]
async fn a_turn_still_over_budget_deepens_the_previous_turns_cut() {
    let mut history = conversation();
    history.extend([
        said("five"),
        replied("six"),
        said("seven"),
        replied("eight"),
    ]);

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

/// Compaction is a view of the conversation, not a mutation of it. A caller appends
/// `outcome.messages` to its own stored history, so anything compaction removed from
/// *that* would be gone for good and the loss would compound every turn.
#[tokio::test]
async fn compaction_does_not_shorten_the_returned_transcript() {
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

/// The API rejects a conversation that does not open on a user turn, and index 1 of
/// this history is the assistant's. Pinned on the serialized request, because that is
/// where the invariant is actually tested in production.
#[tokio::test]
async fn the_request_still_opens_with_a_user_message_after_compaction() {
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

/// The central adversarial case. An orphaned `tool_result` — one whose `tool_use` was
/// withheld — is rejected outright, and in a tool-heavy transcript most indices are
/// one, so the arithmetic alone would land on an invalid cut most of the time.
#[tokio::test]
async fn compaction_never_withholds_a_tool_result_from_the_call_it_answers() {
    let history = vec![
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
    ];
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

/// Rung 3 of the fallback ladder. When every candidate is a tool-result continuation
/// there is no legal cut, and sending the request uncompacted is right: cutting anyway
/// turns a request that *might* be too long into one the API is certain to reject.
#[tokio::test]
async fn an_unbreakable_history_is_sent_oversized_rather_than_cut_invalid() {
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

/// The prompt cache keys on the request's prefix. A cut that moved between rounds would
/// invalidate it on every round of every turn — and would show the model history it had
/// already been denied.
#[tokio::test]
async fn a_cut_chosen_in_one_round_is_reused_by_every_later_round() {
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

/// The oscillation case, and the reason the cut is frozen. Round one's own measurement
/// comes back *under* budget; round two must not put the dropped history back, which
/// would rewrite the cached prefix and re-show what the model had already lost.
#[tokio::test]
async fn usage_falling_back_under_budget_mid_turn_does_not_put_the_history_back() {
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
async fn a_keep_recent_smaller_than_the_turns_own_output_still_sends_that_output() {
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
async fn a_budget_of_zero_compacts_every_turn_that_reported_any_tokens() {
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
/// unchanged with it on. The coupling runs the other way — withholding history is one
/// of the things that can confuse a model into an empty round — and a turn that ends
/// there must still be discarded rather than handed back looking finished.
#[tokio::test]
async fn a_compacted_turn_that_ends_mid_tool_use_is_still_an_error() {
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
