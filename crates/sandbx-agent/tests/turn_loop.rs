//! Public contract of [`run_turn`]: what one streamed turn becomes.
//!
//! Every test drives the loop through the closure seam `run_turn` is generic
//! over, with `MockProvider` on the other side of it, so the whole suite runs
//! with no network access and no API key. Assertions on the rebuilt history go
//! through `serde_json::to_value`, because `ContentBlock` is `Serialize`-only and
//! has no `PartialEq` to compare against.

use std::collections::VecDeque;
use std::future::Future;

use sandbx_agent::{Turn, TurnError, TurnLimits, run_turn};
use sandbx_core::SandboxPolicy;
use sandbx_providers::{
    AgentEvent, EventStream, MessagesRequest, MockProvider, ProviderError, RequestMessage, Role,
    StopReason,
};
use sandbx_tools::{BuiltinTool, ExecutionContext};

/// Scripts one canned round per call, and records what was sent.
///
/// This is the seam itself. `run_turn` asks for a closure that opens a stream, so
/// a test hands it one that pops a canned round off the front. `MockProvider`
/// consuming `self` is exactly right here — each round gets a fresh one — which
/// is why driving a multi-round loop needs no change to `sandbx-providers`, and
/// why recording the requests can live in the test rather than in the double.
struct Script {
    rounds: VecDeque<Vec<AgentEvent>>,
    /// Replayed once `rounds` runs dry, for the tests that need a turn which never
    /// stops asking for tools.
    forever: Option<Vec<AgentEvent>>,
    sent: Vec<MessagesRequest>,
}

impl Script {
    fn new(rounds: impl IntoIterator<Item = Vec<AgentEvent>>) -> Self {
        Self {
            rounds: rounds.into_iter().collect(),
            forever: None,
            sent: Vec::new(),
        }
    }

    /// The same round, over and over, however many times it is asked for.
    fn looping(round: Vec<AgentEvent>) -> Self {
        Self {
            rounds: VecDeque::new(),
            forever: Some(round),
            sent: Vec::new(),
        }
    }

    /// Deliberately not an `async fn`: the future has to own everything it needs
    /// so `run_turn`'s single `Fut` type does not capture the `&mut self` borrow
    /// taken here. `+ use<>` is what states that, the same idiom
    /// `AnthropicClient::stream_chat` uses for the same reason.
    fn open(
        &mut self,
        request: MessagesRequest,
    ) -> impl Future<Output = Result<EventStream, ProviderError>> + use<> {
        self.sent.push(request.clone());
        let events = self
            .rounds
            .pop_front()
            .or_else(|| self.forever.clone())
            .unwrap_or_default();
        MockProvider::new(events).stream_chat(request)
    }
}

fn turn<'a>(history: &'a [RequestMessage], tools: &'a [BuiltinTool]) -> Turn<'a> {
    Turn {
        model: "claude-opus-5".to_string(),
        max_tokens: 1024,
        system: None,
        tools,
        history,
        limits: TurnLimits::default(),
    }
}

/// A context granting nothing, for the tests that never run a tool.
fn ctx() -> ExecutionContext {
    ExecutionContext::new(SandboxPolicy::default())
}

fn text(delta: &str) -> AgentEvent {
    AgentEvent::Text {
        delta: delta.to_string(),
    }
}

fn stop(reason: StopReason) -> AgentEvent {
    AgentEvent::Stop { reason }
}

/// The rebuilt history in the only form `ContentBlock` can be compared in.
fn wire(messages: &[RequestMessage]) -> serde_json::Value {
    serde_json::to_value(messages).unwrap()
}

#[tokio::test]
async fn text_deltas_accumulate_into_one_block() {
    let mut script = Script::new([vec![text("Hel"), text("lo"), stop(StopReason::EndTurn)]]);

    let messages = run_turn(|r| script.open(r), turn(&[], &[]), &ctx(), |_| {})
        .await
        .unwrap();

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
        |r| script.open(r),
        turn(&[], &[]),
        &ctx(),
        |event: &AgentEvent| seen.push(event.clone()),
    )
    .await
    .unwrap();

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
        |r| script.open(r),
        turn(&[], &[]),
        &ctx(),
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

    let messages = run_turn(|r| script.open(r), turn(&[], &[]), &ctx(), |_| {})
        .await
        .unwrap();

    assert!(messages.is_empty(), "got {:?}", wire(&messages));
}

/// A real provider ends a turn with `Stop` or with an `Err`, never with silence.
/// Treating a silent end as success would hand back a turn nothing can tell apart
/// from a truncated one.
#[tokio::test]
async fn a_stream_that_never_reports_a_stop_is_an_error() {
    let mut script = Script::new([vec![text("cut off")]]);

    let error = run_turn(|r| script.open(r), turn(&[], &[]), &ctx(), |_| {})
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
        |r| script.open(r),
        turn(&history, &[BuiltinTool::Read]),
        &ctx(),
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
    let ctx = ExecutionContext::new(SandboxPolicy::default().allow_write(root.path()));

    let mut script = Script::new([
        vec![
            text("Writing it now."),
            AgentEvent::ToolCallRequested {
                id: "call_1".to_string(),
                name: "write".to_string(),
                input: input.clone(),
            },
            stop(StopReason::ToolUse),
        ],
        vec![text("Done."), stop(StopReason::EndTurn)],
    ]);

    let messages = run_turn(
        |r| script.open(r),
        turn(&[], &[BuiltinTool::Write]),
        &ctx,
        |_| {},
    )
    .await
    .unwrap();

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
    let ctx = ExecutionContext::new(SandboxPolicy::default().allow_read(root.path()));

    let mut script = Script::new([
        vec![
            AgentEvent::ToolCallRequested {
                id: "call_1".to_string(),
                name: "ls".to_string(),
                input: serde_json::json!({ "path": root.path().to_str().unwrap() }),
            },
            stop(StopReason::Unspecified),
        ],
        vec![text("listed"), stop(StopReason::EndTurn)],
    ]);

    let messages = run_turn(
        |r| script.open(r),
        turn(&[], &[BuiltinTool::Ls]),
        &ctx,
        |_| {},
    )
    .await
    .unwrap();

    assert_eq!(messages.len(), 3, "got {:?}", wire(&messages));
    assert_eq!(script.sent.len(), 2, "the turn should have re-entered");
}

/// A refusal is not a turn-ending failure: the model is told it was refused and
/// gets to ask for something in scope. `context/TOOLS.md` is explicit that the
/// three `ToolError` variants exist because the model reacts to them differently,
/// which only works if they reach it.
#[tokio::test]
async fn a_refused_tool_call_is_reported_to_the_model_as_an_error() {
    let allowed = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let outside = elsewhere.path().join("escape.txt");
    let ctx = ExecutionContext::new(SandboxPolicy::default().allow_write(allowed.path()));

    let mut script = Script::new([
        vec![
            AgentEvent::ToolCallRequested {
                id: "call_1".to_string(),
                name: "write".to_string(),
                input: serde_json::json!({
                    "path": outside.to_str().unwrap(),
                    "content": "nope",
                }),
            },
            stop(StopReason::ToolUse),
        ],
        vec![
            text("I will stay inside the root."),
            stop(StopReason::EndTurn),
        ],
    ]);

    let messages = run_turn(
        |r| script.open(r),
        turn(&[], &[BuiltinTool::Write]),
        &ctx,
        |_| {},
    )
    .await
    .unwrap();

    assert!(!outside.exists(), "the write must not have happened");

    let result = &wire(&messages)[1]["content"][0];
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
    let ctx = ExecutionContext::new(SandboxPolicy::default().allow_write(root.path()));

    let mut script = Script::new([
        vec![
            AgentEvent::ToolCallRequested {
                id: "call_1".to_string(),
                name: "write".to_string(),
                // `content` is required, and absent.
                input: serde_json::json!({ "path": root.path().join("x").to_str().unwrap() }),
            },
            stop(StopReason::ToolUse),
        ],
        vec![text("Retrying properly."), stop(StopReason::EndTurn)],
    ]);

    let messages = run_turn(
        |r| script.open(r),
        turn(&[], &[BuiltinTool::Write]),
        &ctx,
        |_| {},
    )
    .await
    .unwrap();

    let result = &wire(&messages)[1]["content"][0];
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
        vec![
            AgentEvent::ToolCallRequested {
                id: "call_1".to_string(),
                name: "rm".to_string(),
                input: serde_json::json!({}),
            },
            stop(StopReason::ToolUse),
        ],
        vec![text("Using a real tool."), stop(StopReason::EndTurn)],
    ]);

    let messages = run_turn(
        |r| script.open(r),
        turn(&[], &[BuiltinTool::Write]),
        &ctx(),
        |_| {},
    )
    .await
    .unwrap();

    let result = &wire(&messages)[1]["content"][0];
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
    let ctx = ExecutionContext::new(SandboxPolicy::default().allow_read(root.path()));
    let mut script = Script::looping(vec![
        AgentEvent::ToolCallRequested {
            id: "call_1".to_string(),
            name: "ls".to_string(),
            input: serde_json::json!({ "path": root.path().to_str().unwrap() }),
        },
        stop(StopReason::ToolUse),
    ]);

    let mut asking_forever = turn(&[], &[BuiltinTool::Ls]);
    asking_forever.limits = TurnLimits {
        max_rounds: 3,
        ..TurnLimits::default()
    };

    let error = run_turn(|r| script.open(r), asking_forever, &ctx, |_| {})
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

/// `sandbx-providers` bounds *inactivity between chunks* at 120s and says plainly
/// that a per-turn wall-clock bound "belongs one layer up, wrapping the consumption
/// loop". This is that layer. Without it, a server that keeps the connection warm
/// while producing nothing useful holds a turn open indefinitely.
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
        |_| std::future::ready(Ok(stalled())),
        stalling,
        &ctx(),
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
