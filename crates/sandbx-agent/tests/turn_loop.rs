//! Public contract of `run_turn`: what one streamed turn becomes.
//!
//! Driven through the closure seam with `support::Script`, so the suite needs no network
//! and no API key. Assertions go through `serde_json::to_value`: `ContentBlock` has no
//! `PartialEq`.

use sandbx_agent::{ApprovalDecision, ToolCall, TurnError, TurnLimits, run_turn};
use sandbx_core::SandboxPolicy;
use sandbx_providers::{AgentEvent, EventStream, RequestMessage, Role, StopReason};
use sandbx_tools::{BuiltinTool, ExecutionContext};

mod support;

use support::{Script, allow_all, call, ctx, stop, text, turn, wire};

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
        allow_all,
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

/// The signature Anthropic streams alongside a thinking block is discarded upstream, so
/// it cannot be replayed — but a TUI still has to see it (#85).
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
        allow_all,
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

/// Text arrives as increments, so a renderer needs each event as it lands.
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
        allow_all,
    )
    .await
    .unwrap();

    assert_eq!(seen, round);
}

/// The API rejects an empty content array, so appending one poisons every later
/// request.
#[tokio::test]
async fn a_round_that_produced_nothing_appends_no_message() {
    let mut script = Script::new([vec![stop(StopReason::EndTurn)]]);

    let messages = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[]),
        &ctx(SandboxPolicy::default()),
        |_| {},
        allow_all,
    )
    .await
    .unwrap()
    .messages;

    assert!(messages.is_empty(), "got {:?}", wire(&messages));
}

/// A real provider never ends with silence, and a silent end read as success is
/// indistinguishable from a truncated turn.
#[tokio::test]
async fn a_stream_that_never_reports_a_stop_is_an_error() {
    let mut script = Script::new([vec![text("cut off")]]);

    let error = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[]),
        &ctx(SandboxPolicy::default()),
        |_| {},
        allow_all,
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
        allow_all,
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

/// The loop end to end, including that the second round carries the first.
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
        allow_all,
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

/// `message_delta.stop_reason` is nullable, so keying re-entry off the reason rather
/// than the calls would silently drop a round's tool calls.
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
        allow_all,
    )
    .await
    .unwrap()
    .messages;

    assert_eq!(messages.len(), 3, "got {:?}", wire(&messages));
    assert_eq!(script.sent.len(), 2, "the turn should have re-entered");
}

/// A refusal is not a turn-ending failure: the model is told, and gets to ask for
/// something in scope. See `context/guide-tools.md`.
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
        allow_all,
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

/// Arguments off the schema are the model's mistake to fix, not the turn's to die of.
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
        allow_all,
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

/// `from_name` is exact-match, so an unresolved name is a prompt or schema bug the model
/// is the one to correct. Nothing runs.
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
        allow_all,
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

/// The policy allows the write, so the `is_error` block alone would pass even if the
/// file had been written.
#[tokio::test]
async fn a_denied_call_never_reaches_the_tool() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("note.txt");
    let ctx = ctx(SandboxPolicy::default().allow_write(root.path()));

    let mut script = Script::new([
        vec![
            call(
                "write",
                serde_json::json!({ "path": file.to_str().unwrap(), "content": "written" }),
            ),
            stop(StopReason::ToolUse),
        ],
        vec![text("Understood."), stop(StopReason::EndTurn)],
    ]);

    let messages = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Write]),
        &ctx,
        |_| {},
        |_| ApprovalDecision::Deny {
            reason: "write is not approved for this run".to_string(),
        },
    )
    .await
    .unwrap()
    .messages;

    assert!(!file.exists(), "a refused call must not have run");

    let result = tool_error(&messages);
    assert_eq!(result["is_error"], true);
    assert_eq!(result["content"], "write is not approved for this run");
}

/// The gate that refused once is asked again rather than latched shut.
#[tokio::test]
async fn a_denial_never_ends_the_turn() {
    let root = tempfile::tempdir().unwrap();
    let ctx = ctx(SandboxPolicy::default()
        .allow_read(root.path())
        .allow_write(root.path()));

    let mut script = Script::new([
        vec![
            call(
                "write",
                serde_json::json!({
                    "path": root.path().join("x").to_str().unwrap(),
                    "content": "x",
                }),
            ),
            stop(StopReason::ToolUse),
        ],
        vec![
            call(
                "ls",
                serde_json::json!({ "path": root.path().to_str().unwrap() }),
            ),
            stop(StopReason::ToolUse),
        ],
        vec![text("Listed instead."), stop(StopReason::EndTurn)],
    ]);

    let messages = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Write, BuiltinTool::Ls]),
        &ctx,
        |_| {},
        |requested: ToolCall<'_>| match requested.tool {
            BuiltinTool::Write => ApprovalDecision::Deny {
                reason: "write is not approved".to_string(),
            },
            _ => ApprovalDecision::Allow,
        },
    )
    .await
    .unwrap()
    .messages;

    assert_eq!(
        script.sent.len(),
        3,
        "the turn should have re-entered twice"
    );

    // The second call's result: the same gate, asked again, let this one through.
    let listed = wire(&messages)[3]["content"][0].clone();
    assert_eq!(
        listed["is_error"],
        serde_json::Value::Null,
        "got {listed:?}"
    );
}

/// Before, not alongside: `spawn_blocking` cannot be cancelled, so a late decision would
/// refuse a call that had already landed (#26).
#[tokio::test]
async fn the_gate_sees_a_call_before_it_runs() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("note.txt");
    let input = serde_json::json!({ "path": file.to_str().unwrap(), "content": "written" });
    let ctx = ctx(SandboxPolicy::default().allow_write(root.path()));

    let mut script = Script::new([
        vec![call("write", input.clone()), stop(StopReason::ToolUse)],
        vec![text("Done."), stop(StopReason::EndTurn)],
    ]);
    let mut seen = Vec::new();

    run_turn(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Write]),
        &ctx,
        |_| {},
        |requested: ToolCall<'_>| {
            seen.push((
                requested.tool,
                requested.id.to_string(),
                requested.input.clone(),
                file.exists(),
            ));
            ApprovalDecision::Allow
        },
    )
    .await
    .unwrap();

    assert_eq!(
        seen,
        vec![(BuiltinTool::Write, "call_1".to_string(), input, false)]
    );
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "written");
}

/// A gate decides about tools, and an unresolved name is not one.
#[tokio::test]
async fn an_unknown_name_never_reaches_the_gate() {
    let mut script = Script::new([
        vec![call("rm", serde_json::json!({})), stop(StopReason::ToolUse)],
        vec![text("Using a real tool."), stop(StopReason::EndTurn)],
    ]);
    let mut asked = 0usize;

    let messages = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Write]),
        &ctx(SandboxPolicy::default()),
        |_| {},
        |_| {
            asked += 1;
            ApprovalDecision::Allow
        },
    )
    .await
    .unwrap()
    .messages;

    assert_eq!(asked, 0, "a name no tool answers to reached the gate");
    assert_eq!(tool_error(&messages)["is_error"], true);
}

/// `from_name` resolves against every built-in, so resolving alone would let an
/// allow-all gate run a call the turn never offered.
#[tokio::test]
async fn an_un_offered_tool_never_reaches_the_gate() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("note.txt");
    let ctx = ctx(SandboxPolicy::default().allow_write(root.path()));

    let mut script = Script::new([
        vec![
            call(
                "write",
                serde_json::json!({ "path": file.to_str().unwrap(), "content": "written" }),
            ),
            stop(StopReason::ToolUse),
        ],
        vec![text("Understood."), stop(StopReason::EndTurn)],
    ]);
    let mut asked = 0usize;

    // The policy would let the write through, so the offered set is the single thing
    // standing between the call and the file.
    let messages = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Ls]),
        &ctx,
        |_| {},
        |_| {
            asked += 1;
            ApprovalDecision::Allow
        },
    )
    .await
    .unwrap()
    .messages;

    assert_eq!(asked, 0, "a tool the turn never offered reached the gate");
    assert!(!file.exists(), "an un-offered call must not have run");
    assert_eq!(tool_error(&messages)["is_error"], true);
}

/// Each answer needs its own `tool_use_id`, or the model reads the refusal as belonging
/// to the call that succeeded.
#[tokio::test]
async fn a_round_of_two_calls_gets_a_verdict_each() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("note.txt");
    let ctx = ctx(SandboxPolicy::default()
        .allow_read(root.path())
        .allow_write(root.path()));

    let mut script = Script::new([
        vec![
            call_id(
                "denied",
                "write",
                serde_json::json!({ "path": file.to_str().unwrap(), "content": "written" }),
            ),
            call_id(
                "allowed",
                "ls",
                serde_json::json!({ "path": root.path().to_str().unwrap() }),
            ),
            stop(StopReason::ToolUse),
        ],
        vec![text("One of two."), stop(StopReason::EndTurn)],
    ]);

    let messages = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Write, BuiltinTool::Ls]),
        &ctx,
        |_| {},
        |requested: ToolCall<'_>| match requested.tool {
            BuiltinTool::Write => ApprovalDecision::Deny {
                reason: "write is not approved".to_string(),
            },
            _ => ApprovalDecision::Allow,
        },
    )
    .await
    .unwrap()
    .messages;

    assert!(!file.exists(), "the refused call must not have run");

    let results = wire(&messages)[1]["content"].clone();
    assert_eq!(results[0]["tool_use_id"], "denied");
    assert_eq!(results[0]["is_error"], true);
    assert_eq!(results[0]["content"], "write is not approved");
    assert_eq!(results[1]["tool_use_id"], "allowed");
    assert_eq!(
        results[1]["is_error"],
        serde_json::Value::Null,
        "got {:?}",
        results[1]
    );
}

/// A scripted call with an explicit id, for a round that makes more than one.
fn call_id(id: &str, name: &str, input: serde_json::Value) -> AgentEvent {
    AgentEvent::ToolCallRequested {
        id: id.to_string(),
        name: name.to_string(),
        input,
    }
}

/// A model that keeps asking for tools, looping on its own or steered into it by
/// injected content, would otherwise drive tool execution without bound.
#[tokio::test]
async fn a_turn_ends_once_it_runs_out_of_rounds() {
    let root = tempfile::tempdir().unwrap();
    let ctx = ctx(SandboxPolicy::default().allow_read(root.path()));
    // Exactly as many as the cap allows: an endless supply would hide the dependency.
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

    let error = run_turn(
        async |r| script.open(r).await,
        asking_forever,
        &ctx,
        |_| {},
        allow_all,
    )
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

/// A stream that opens and then goes quiet forever. `stream::pending` satisfies the
/// `FusedStream` `EventStream` promises: it never yields and never claims termination.
fn stalled() -> EventStream {
    Box::pin(futures_util::stream::pending())
}

/// A connection kept warm while producing nothing would otherwise hold a turn open; see
/// `TurnLimits::stream_timeout` for why the provider's read timeout does not cover it.
/// Paused time, so the runtime auto-advances rather than waiting the bound out.
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
        allow_all,
    )
    .await
    .expect_err("a stream that never finishes must not hold the turn open");

    assert!(
        matches!(error, TurnError::TimedOut { after } if after == std::time::Duration::from_secs(30)),
        "got {error:?}"
    );
}

/// Pinned literally, like the round cap. It bounds one round's whole generation and does
/// not replace the per-chunk read timeout underneath it.
#[test]
fn the_default_stream_bound_is_the_documented_one() {
    assert_eq!(
        TurnLimits::default().stream_timeout,
        std::time::Duration::from_secs(300)
    );
}

/// The call shape `run_turn`'s docs promise, compiled but never run: a plain non-async
/// closure, which `AsyncFnMut` accepts through the blanket impl for `FnMut(..) -> Future`.
/// Also pins that the future is `Send`, the one thing a named `Fut` would have bought.
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
        allow_all,
    ));
}

/// A round producing nothing *after* tools have run ends the transcript on an unanswered
/// `tool_result`, which breaks the *next* request rather than this one.
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
        allow_all,
    )
    .await
    .expect_err("a transcript ending in an unanswered tool_result is not a turn");

    assert!(matches!(error, TurnError::EndedMidToolUse), "got {error:?}");
}
