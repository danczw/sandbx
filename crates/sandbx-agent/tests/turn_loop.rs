//! Public contract of `run_turn`: what one streamed turn becomes.
//!
//! Driven through the closure seam with `support::Script`, so the suite needs no network
//! and no API key.

use sandbx_agent::{
    ApprovalDecision, CallGate, Outcome, Settled, ToolCall, TurnError, TurnLimits, TurnStop,
    run_turn,
};
use sandbx_core::SandboxPolicy;
use sandbx_providers::{AgentEvent, ContentBlock, EventStream, RequestMessage, Role, StopReason};
use sandbx_tools::{BuiltinTool, ExecutionContext};

mod support;

use support::{AllowAll, Script, call, ctx, stop, text, turn, vetted};

/// An assistant turn of prose, the shape most of these end on.
fn replied(text: &str) -> RequestMessage {
    RequestMessage {
        role: Role::Assistant,
        content: vec![ContentBlock::Text {
            text: text.to_string(),
        }],
    }
}

/// A `tool_result`'s answer and verdict, for the assertions whose subject is one.
///
/// Panics on anything else: a scripted tool call produces one, so another block is a bug.
fn result_of(block: &ContentBlock) -> (&str, Option<bool>) {
    match block {
        ContentBlock::ToolResult {
            content, is_error, ..
        } => (content, *is_error),
        other => panic!("not a tool_result: {other:?}"),
    }
}

/// A gate whose verdict is a closure's, keeping what it was asked and what it was told.
///
/// Lent to `run_turn` as `&mut gate`, so both records survive the turn. Here rather than
/// in `support`, which only holds what both halves of the suite use.
struct Gate<F> {
    decide: F,

    /// One entry per call that reached [`CallGate::approve`], which three outcomes do not.
    asked: Vec<(BuiltinTool, String, serde_json::Value)>,

    /// One `{name}:{outcome}` per `tool_use` block, in the order the round settled them.
    settled: Vec<String>,
}

impl<F: FnMut(ToolCall<'_>) -> ApprovalDecision> Gate<F> {
    fn new(decide: F) -> Self {
        Self {
            decide,
            asked: Vec::new(),
            settled: Vec::new(),
        }
    }
}

impl<F: FnMut(ToolCall<'_>) -> ApprovalDecision> CallGate for Gate<F> {
    fn approve(&mut self, call: ToolCall<'_>) -> ApprovalDecision {
        self.asked
            .push((call.tool, call.id.to_string(), call.input.clone()));
        (self.decide)(call)
    }

    fn settled(&mut self, call: Settled<'_>) {
        let outcome = match call.outcome {
            Outcome::Unknown => "unknown",
            Outcome::NotOffered => "not-offered",
            Outcome::Denied { .. } => "denied",
            Outcome::Ran => "ran",
            Outcome::Errored(_) => "errored",
        };
        self.settled.push(format!("{}:{outcome}", call.name));
    }
}

/// The single `tool_result` block a scripted call produced.
fn tool_error(messages: &[RequestMessage]) -> (&str, Option<bool>) {
    result_of(&messages[1].content[0])
}

#[tokio::test]
async fn text_deltas_accumulate_into_one_block() {
    let mut script = Script::new([vec![text("Hel"), text("lo"), stop(StopReason::EndTurn)]]);

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[]),
        &ctx(SandboxPolicy::default()),
        |_| {},
        AllowAll,
    )
    .await
    .unwrap();

    assert_eq!(outcome.messages, vec![replied("Hello")]);
    assert_eq!(outcome.stop, TurnStop::Answered);
}

/// Both halves, because either on its own passes for the wrong reason: a loop that never
/// replayed thinking would satisfy the second, and one that never stripped it the first.
/// See `context/decision-thinking-replay.md`.
#[tokio::test]
async fn thinking_is_replayed_in_turn_and_never_out() {
    let root = tempfile::tempdir().unwrap();
    let delta = AgentEvent::Thinking {
        delta: "weighing it up".to_string(),
    };
    let block = ContentBlock::Thinking {
        text: "weighing it up".to_string(),
        signature: "sig-1".to_string(),
    };

    let mut script = Script::new([
        vec![
            delta.clone(),
            AgentEvent::ThinkingBlock {
                text: "weighing it up".to_string(),
                signature: "sig-1".to_string(),
            },
            call(
                "ls",
                serde_json::json!({ "path": root.path().to_str().unwrap() }),
            ),
            stop(StopReason::ToolUse),
        ],
        vec![text("done"), stop(StopReason::EndTurn)],
    ]);
    let mut seen = Vec::new();

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Ls]),
        &ctx(SandboxPolicy::default().allow_read(vetted(root.path()))),
        |event: &AgentEvent| seen.push(event.clone()),
        AllowAll,
    )
    .await
    .unwrap();

    // Round two replays it, signature and all.
    let replayed = &script.sent[1].messages;
    assert!(
        replayed
            .iter()
            .any(|message| message.content.contains(&block)),
        "got {replayed:?}"
    );

    // And nothing a caller stores carries one.
    assert!(
        !outcome
            .messages
            .iter()
            .any(|message| message.content.iter().any(is_thinking)),
        "got {:?}",
        outcome.messages
    );

    assert!(seen.contains(&delta), "got {seen:?}");
}

/// Reasoning of either kind, since the provider checks for a gap rather than for a type.
#[tokio::test]
async fn redacted_thinking_is_stripped_from_the_outcome() {
    let mut script = Script::new([vec![
        AgentEvent::RedactedThinking {
            data: "opaque".to_string(),
        },
        text("done"),
        stop(StopReason::EndTurn),
    ]]);

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[]),
        &ctx(SandboxPolicy::default()),
        |_| {},
        AllowAll,
    )
    .await
    .unwrap();

    assert_eq!(outcome.messages, vec![replied("done")]);
}

/// A round that reasoned and said nothing else leaves a message with no content, which no
/// provider accepts — so the message goes too, not just the block.
#[tokio::test]
async fn a_turn_of_only_thinking_produces_no_message() {
    let mut script = Script::new([vec![
        AgentEvent::ThinkingBlock {
            text: "quietly".to_string(),
            signature: "sig-1".to_string(),
        },
        stop(StopReason::EndTurn),
    ]]);

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[]),
        &ctx(SandboxPolicy::default()),
        |_| {},
        AllowAll,
    )
    .await
    .unwrap();

    assert!(outcome.messages.is_empty(), "got {:?}", outcome.messages);
    assert_eq!(outcome.stop, TurnStop::Answered);
}

fn is_thinking(block: &ContentBlock) -> bool {
    matches!(
        block,
        ContentBlock::Thinking { .. } | ContentBlock::RedactedThinking { .. }
    )
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
            cache_write_tokens: None,
            cache_read_tokens: None,
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
        AllowAll,
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

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[]),
        &ctx(SandboxPolicy::default()),
        |_| {},
        AllowAll,
    )
    .await
    .unwrap();

    assert!(outcome.messages.is_empty(), "got {:?}", outcome.messages);
    assert_eq!(outcome.stop, TurnStop::Answered);
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
        AllowAll,
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
        content: vec![ContentBlock::Text {
            text: "hello".to_string(),
        }],
    }];
    let mut script = Script::new([vec![text("hi"), stop(StopReason::EndTurn)]]);

    run_turn(
        async |r| script.open(r).await,
        turn(&history, &[BuiltinTool::Read]),
        &ctx(SandboxPolicy::default()),
        |_| {},
        AllowAll,
    )
    .await
    .unwrap();

    let sent = &script.sent[0];
    assert_eq!(sent.model, "claude-opus-5");
    assert_eq!(sent.max_output_tokens, 1024);
    assert_eq!(sent.messages, history);
    assert_eq!(sent.tools.len(), 1, "got {:?}", sent.tools);
    assert_eq!(sent.tools[0].name, BuiltinTool::Read.name());
    assert_eq!(sent.tools[0].description, BuiltinTool::Read.description());
    assert_eq!(sent.tools[0].schema, BuiltinTool::Read.input_schema());
}

/// The loop end to end, including that the second round carries the first.
#[tokio::test]
async fn a_tool_result_is_fed_into_the_next_round() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("note.txt");
    let input = serde_json::json!({ "path": file.to_str().unwrap(), "content": "written" });
    let ctx = ctx(SandboxPolicy::default().allow_write(vetted(root.path())));

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
        AllowAll,
    )
    .await
    .unwrap()
    .messages;

    assert_eq!(std::fs::read_to_string(&file).unwrap(), "written");

    assert_eq!(
        messages,
        vec![
            RequestMessage {
                role: Role::Assistant,
                content: vec![
                    ContentBlock::Text {
                        text: "Writing it now.".to_string(),
                    },
                    ContentBlock::ToolUse {
                        id: "call_1".to_string(),
                        name: "write".to_string(),
                        input,
                    },
                ],
            },
            RequestMessage {
                role: Role::User,
                content: vec![ContentBlock::ToolResult {
                    tool_use_id: "call_1".to_string(),
                    content: format!("wrote 7 bytes to {}", file.display()),
                    is_error: None,
                }],
            },
            replied("Done."),
        ]
    );

    // The second round has to carry the first one, or the model answers blind.
    assert_eq!(script.sent[1].messages, messages[..2]);
}

/// `message_delta.stop_reason` is nullable, so keying re-entry off the reason rather
/// than the calls would silently drop a round's tool calls.
#[tokio::test]
async fn a_tool_call_runs_without_a_stop_reason() {
    let root = tempfile::tempdir().unwrap();
    let ctx = ctx(SandboxPolicy::default().allow_read(vetted(root.path())));

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
        AllowAll,
    )
    .await
    .unwrap()
    .messages;

    assert_eq!(messages.len(), 3, "got {messages:?}");
    assert_eq!(script.sent.len(), 2, "the turn should have re-entered");
}

/// A refusal is not a turn-ending failure: the model is told, and gets to ask for
/// something in scope. See `context/guide-tools.md`.
#[tokio::test]
async fn a_refused_tool_call_is_an_error_to_the_model() {
    let allowed = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let outside = elsewhere.path().join("escape.txt");
    let ctx = ctx(SandboxPolicy::default().allow_write(vetted(allowed.path())));

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

    let mut gate = Gate::new(|_| ApprovalDecision::Allow);
    let messages = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Write]),
        &ctx,
        |_| {},
        &mut gate,
    )
    .await
    .unwrap()
    .messages;

    assert!(!outside.exists(), "the write must not have happened");

    let (content, is_error) = tool_error(&messages);
    assert_eq!(is_error, Some(true));
    assert!(
        content.contains("refused by the sandbox policy"),
        "got {content:?}"
    );
    assert_eq!(messages.len(), 3, "the turn should have carried on");
    // #169's misleading row: the gate said yes and the policy then said no, so a report
    // built from the verdict alone would announce a write that never happened.
    assert_eq!(gate.asked.len(), 1, "the gate approved nothing");
    assert_eq!(gate.settled, ["write:errored"]);
}

/// Arguments off the schema are the model's mistake to fix, not the turn's to die of.
#[tokio::test]
async fn bad_tool_arguments_are_reported_as_an_error() {
    let root = tempfile::tempdir().unwrap();
    let ctx = ctx(SandboxPolicy::default().allow_write(vetted(root.path())));

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
        AllowAll,
    )
    .await
    .unwrap()
    .messages;

    let (content, is_error) = tool_error(&messages);
    assert_eq!(is_error, Some(true));
    assert!(
        content.contains("invalid tool arguments"),
        "got {content:?}"
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
        AllowAll,
    )
    .await
    .unwrap()
    .messages;

    let (content, is_error) = tool_error(&messages);
    assert_eq!(is_error, Some(true));
    assert!(content.contains("rm"), "got {content:?}");
    assert_eq!(messages.len(), 3, "the turn should have carried on");
}

/// The policy allows the write, so the `is_error` block alone would pass even if the
/// file had been written.
#[tokio::test]
async fn a_denied_call_never_reaches_the_tool() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("note.txt");
    let ctx = ctx(SandboxPolicy::default().allow_write(vetted(root.path())));

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

    let mut gate = Gate::new(|_| ApprovalDecision::Deny {
        reason: "write is not approved for this run".to_string(),
    });
    let messages = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Write]),
        &ctx,
        |_| {},
        &mut gate,
    )
    .await
    .unwrap()
    .messages;

    assert!(!file.exists(), "a refused call must not have run");

    assert_eq!(
        tool_error(&messages),
        ("write is not approved for this run", Some(true))
    );
    assert_eq!(
        gate.settled,
        ["write:denied"],
        "the gate's own refusal was not reported back to it"
    );
}

/// The gate that refused once is asked again rather than latched shut.
#[tokio::test]
async fn a_denial_never_ends_the_turn() {
    let root = tempfile::tempdir().unwrap();
    let ctx = ctx(SandboxPolicy::default()
        .allow_read(vetted(root.path()))
        .allow_write(vetted(root.path())));

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

    let mut gate = Gate::new(|requested: ToolCall<'_>| match requested.tool {
        BuiltinTool::Write => ApprovalDecision::Deny {
            reason: "write is not approved".to_string(),
        },
        _ => ApprovalDecision::Allow,
    });
    let messages = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Write, BuiltinTool::Ls]),
        &ctx,
        |_| {},
        &mut gate,
    )
    .await
    .unwrap()
    .messages;

    assert_eq!(
        script.sent.len(),
        3,
        "the turn should have re-entered twice"
    );
    assert_eq!(
        gate.settled,
        ["write:denied", "ls:ran"],
        "the gate latched shut after refusing once"
    );

    // The second call's result: the same gate, asked again, let this one through.
    let listed = result_of(&messages[3].content[0]);
    assert_eq!(listed.1, None, "got {listed:?}");
}

/// Before, not alongside: `spawn_blocking` cannot be cancelled, so a late decision would
/// refuse a call that had already landed (#26).
#[tokio::test]
async fn the_gate_sees_a_call_before_it_runs() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("note.txt");
    let input = serde_json::json!({ "path": file.to_str().unwrap(), "content": "written" });
    let ctx = ctx(SandboxPolicy::default().allow_write(vetted(root.path())));

    let mut script = Script::new([
        vec![call("write", input.clone()), stop(StopReason::ToolUse)],
        vec![text("Done."), stop(StopReason::EndTurn)],
    ]);
    // Asserted inside the gate rather than after the turn: afterwards the file exists
    // either way, so only the verdict's own moment can show the order.
    let mut gate = Gate::new(|_| {
        assert!(!file.exists(), "the call ran before the gate was asked");
        ApprovalDecision::Allow
    });

    run_turn(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Write]),
        &ctx,
        |_| {},
        &mut gate,
    )
    .await
    .unwrap();

    assert_eq!(
        gate.asked,
        vec![(BuiltinTool::Write, "call_1".to_string(), input)]
    );
    assert_eq!(gate.settled, ["write:ran"]);
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "written");
}

/// A gate decides about tools, and an unresolved name is not one.
#[tokio::test]
async fn an_unknown_name_never_reaches_the_gate() {
    let mut script = Script::new([
        vec![call("rm", serde_json::json!({})), stop(StopReason::ToolUse)],
        vec![text("Using a real tool."), stop(StopReason::EndTurn)],
    ]);
    let mut gate = Gate::new(|_| ApprovalDecision::Allow);

    let messages = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Write]),
        &ctx(SandboxPolicy::default()),
        |_| {},
        &mut gate,
    )
    .await
    .unwrap()
    .messages;

    assert!(
        gate.asked.is_empty(),
        "a name no tool answers to reached the gate"
    );
    // The refusal still reaches the gate as a settled call, which is the record #169
    // found missing.
    assert_eq!(gate.settled, ["rm:unknown"]);
    assert_eq!(tool_error(&messages).1, Some(true));
}

/// `from_name` resolves against every built-in, so resolving alone would let an
/// allow-all gate run a call the turn never offered.
#[tokio::test]
async fn an_un_offered_tool_never_reaches_the_gate() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("note.txt");
    let ctx = ctx(SandboxPolicy::default().allow_write(vetted(root.path())));

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
    let mut gate = Gate::new(|_| ApprovalDecision::Allow);

    // The policy would let the write through, so the offered set is the single thing
    // standing between the call and the file.
    let messages = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Ls]),
        &ctx,
        |_| {},
        &mut gate,
    )
    .await
    .unwrap()
    .messages;

    assert!(
        gate.asked.is_empty(),
        "a tool the turn never offered reached the gate"
    );
    assert_eq!(gate.settled, ["write:not-offered"]);
    assert!(!file.exists(), "an un-offered call must not have run");
    assert_eq!(tool_error(&messages).1, Some(true));
}

/// Each answer needs its own `tool_use_id`, or the model reads the refusal as belonging
/// to the call that succeeded.
#[tokio::test]
async fn a_round_of_two_calls_gets_a_verdict_each() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("note.txt");
    let ctx = ctx(SandboxPolicy::default()
        .allow_read(vetted(root.path()))
        .allow_write(vetted(root.path())));

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

    let mut gate = Gate::new(|requested: ToolCall<'_>| match requested.tool {
        BuiltinTool::Write => ApprovalDecision::Deny {
            reason: "write is not approved".to_string(),
        },
        _ => ApprovalDecision::Allow,
    });
    let messages = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Write, BuiltinTool::Ls]),
        &ctx,
        |_| {},
        &mut gate,
    )
    .await
    .unwrap()
    .messages;

    assert!(!file.exists(), "the refused call must not have run");
    assert_eq!(
        gate.settled,
        ["write:denied", "ls:ran"],
        "a two-call round did not report each call once, in order"
    );

    let results = &messages[1].content;
    assert_eq!(
        results[0],
        ContentBlock::ToolResult {
            tool_use_id: "denied".to_string(),
            content: "write is not approved".to_string(),
            is_error: Some(true),
        }
    );
    // Not pinned on its content, which is the `ls` tool's to answer for.
    assert!(
        matches!(&results[1], ContentBlock::ToolResult { tool_use_id, is_error: None, .. }
            if tool_use_id == "allowed"),
        "got {:?}",
        results[1]
    );
}

/// Both verdicts over one script, because either alone passes for the wrong reason: a loop
/// that ended on every refusal would satisfy the first, and one that ended on none the
/// second. Both scripts hold a second round, so `sent.len() == 1` is evidence no request
/// was opened rather than evidence the script ran dry.
#[tokio::test]
async fn an_abort_ends_the_turn_where_a_deny_goes_on() {
    let root = tempfile::tempdir().unwrap();
    let reason = "the operator's terminal is closed";

    let rounds = || {
        [
            vec![
                text("looking"),
                call(
                    "ls",
                    serde_json::json!({ "path": root.path().to_str().unwrap() }),
                ),
                stop(StopReason::ToolUse),
            ],
            vec![text("found it"), stop(StopReason::EndTurn)],
        ]
    };
    let offered = [BuiltinTool::Ls];
    let ctx = ctx(SandboxPolicy::default().allow_read(vetted(root.path())));

    let mut script = Script::new(rounds());
    let aborted = run_turn(
        async |r| script.open(r).await,
        turn(&[], &offered),
        &ctx,
        |_| {},
        Gate::new(|_: ToolCall<'_>| ApprovalDecision::Abort {
            reason: reason.to_string(),
        }),
    )
    .await
    .unwrap();

    assert_eq!(aborted.stop, TurnStop::GateAborted);
    assert_eq!(
        script.sent.len(),
        1,
        "an aborted turn opened a second request"
    );
    // The replayable shape a session stores: the assistant turn, then the results.
    assert_eq!(aborted.messages.len(), 2);
    assert_eq!(aborted.messages[1].role, Role::User);
    assert_eq!(tool_error(&aborted.messages), (reason, Some(true)));

    let mut script = Script::new(rounds());
    let denied = run_turn(
        async |r| script.open(r).await,
        turn(&[], &offered),
        &ctx,
        |_| {},
        Gate::new(|_: ToolCall<'_>| ApprovalDecision::Deny {
            reason: reason.to_string(),
        }),
    )
    .await
    .unwrap();

    assert_eq!(denied.stop, TurnStop::Answered);
    assert_eq!(
        script.sent.len(),
        2,
        "a refused call ended the turn it was recoverable within"
    );
}

/// Fail-closed: the abort landed on the `write`, so the `bash` behind it must not run on
/// the strength of a verdict the gate was no longer there to give.
#[tokio::test]
async fn the_calls_after_an_abort_are_answered_not_run() {
    let root = tempfile::tempdir().unwrap();
    let behind = root.path().join("behind.txt");
    let ctx = ctx(SandboxPolicy::default()
        .allow_read(vetted(root.path()))
        .allow_write(vetted(root.path())));

    let mut script = Script::new([
        vec![
            call_id(
                "first",
                "ls",
                serde_json::json!({ "path": root.path().to_str().unwrap() }),
            ),
            call_id(
                "aborting",
                "write",
                serde_json::json!({ "path": root.path().join("at.txt").to_str().unwrap(),
                                    "content": "at the abort" }),
            ),
            call_id(
                "behind",
                "write",
                serde_json::json!({ "path": behind.to_str().unwrap(), "content": "behind it" }),
            ),
            stop(StopReason::ToolUse),
        ],
        vec![text("unreachable"), stop(StopReason::EndTurn)],
    ]);

    let mut gate = Gate::new(|requested: ToolCall<'_>| match requested.tool {
        BuiltinTool::Write => ApprovalDecision::Abort {
            reason: "the operator's terminal is closed".to_string(),
        },
        _ => ApprovalDecision::Allow,
    });
    let outcome = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Ls, BuiltinTool::Write]),
        &ctx,
        |_| {},
        &mut gate,
    )
    .await
    .unwrap();

    assert_eq!(outcome.stop, TurnStop::GateAborted);
    assert!(!behind.exists(), "a call behind an abort ran");
    assert_eq!(
        gate.asked.len(),
        2,
        "the call behind the abort was put to a gate that had said it could not answer"
    );
    assert_eq!(
        gate.settled,
        ["ls:ran", "write:denied", "write:denied"],
        "a three-call round did not report each call once, in order"
    );

    let results = &outcome.messages[1].content;
    assert_eq!(results.len(), 3, "got {results:?}");
    // The `ls` consented to before the abort stands: an abort narrows what follows it, it
    // does not retract what already ran.
    assert_eq!(result_of(&results[0]).1, None);
    for behind in &results[1..] {
        assert_eq!(result_of(behind).1, Some(true));
    }
}

/// A scripted call with an explicit id, for a round that makes more than one.
fn call_id(id: &str, name: &str, input: serde_json::Value) -> AgentEvent {
    AgentEvent::ToolCallRequested {
        id: id.to_string(),
        name: name.to_string(),
        input,
    }
}

/// Exactly as many rounds as the cap allows: an endless supply would hide the dependency.
fn asking_forever(root: &std::path::Path) -> Script {
    Script::new(std::iter::repeat_n(
        vec![
            call("ls", serde_json::json!({ "path": root.to_str().unwrap() })),
            stop(StopReason::ToolUse),
        ],
        3,
    ))
}

fn capped_at_three() -> sandbx_agent::Turn<'static> {
    let mut turn = turn(&[], &[BuiltinTool::Ls]);
    turn.limits = TurnLimits {
        max_rounds: 3,
        ..TurnLimits::default()
    };
    turn
}

/// A model looping on its own or steered into it would otherwise drive tools unbounded.
#[tokio::test]
async fn a_turn_stops_asking_once_it_runs_out_of_rounds() {
    let root = tempfile::tempdir().unwrap();
    let ctx = ctx(SandboxPolicy::default().allow_read(vetted(root.path())));
    let mut script = asking_forever(root.path());

    run_turn(
        async |r| script.open(r).await,
        capped_at_three(),
        &ctx,
        |_| {},
        AllowAll,
    )
    .await
    .expect("a turn out of rounds still returns what it did");

    assert_eq!(
        script.sent.len(),
        3,
        "it should have asked exactly three times"
    );
}

/// The shape no truncation would help: every prefix ends on an unanswered `tool_result`.
#[tokio::test]
async fn a_turn_out_of_rounds_hands_back_what_it_did() {
    let root = tempfile::tempdir().unwrap();
    let ctx = ctx(SandboxPolicy::default().allow_read(vetted(root.path())));
    let mut script = asking_forever(root.path());

    let outcome = run_turn(
        async |r| script.open(r).await,
        capped_at_three(),
        &ctx,
        |_| {},
        AllowAll,
    )
    .await
    .unwrap();

    assert_eq!(outcome.stop, TurnStop::RoundLimit { rounds: 3 });
    assert_eq!(outcome.messages.len(), 6, "three rounds, two messages each");
    assert!(matches!(
        outcome.messages.last().map(|last| last.role),
        Some(Role::User)
    ));
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
        AllowAll,
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
        AllowAll,
    ));
}

/// A round producing nothing *after* tools have run ends the transcript on an unanswered
/// `tool_result`, which breaks the *next* request rather than this one.
#[tokio::test]
async fn an_empty_round_mid_tool_use_is_an_error() {
    let root = tempfile::tempdir().unwrap();
    let ctx = ctx(SandboxPolicy::default().allow_read(vetted(root.path())));
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
        AllowAll,
    )
    .await
    .expect_err("a transcript ending in an unanswered tool_result is not a turn");

    assert!(matches!(error, TurnError::EndedMidToolUse), "got {error:?}");
}

/// Reasoning is stripped on the way out, so a round carrying nothing else is the empty
/// round above wearing a block. Reading it as content returns `Answered` over a
/// transcript ending on an unanswered `tool_result`, which a caller stores and the next
/// request is rejected for.
#[tokio::test]
async fn a_reasoning_only_round_mid_tool_use_is_the_same_error() {
    let root = tempfile::tempdir().unwrap();
    let ctx = ctx(SandboxPolicy::default().allow_read(vetted(root.path())));
    let mut script = Script::new([
        vec![
            call(
                "ls",
                serde_json::json!({ "path": root.path().to_str().unwrap() }),
            ),
            stop(StopReason::ToolUse),
        ],
        // Answered the tool, then reasoned and stopped.
        vec![
            AgentEvent::ThinkingBlock {
                text: "weighing it up".to_string(),
                signature: "sig-1".to_string(),
            },
            stop(StopReason::EndTurn),
        ],
    ]);

    let error = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Ls]),
        &ctx,
        |_| {},
        AllowAll,
    )
    .await
    .expect_err("reasoning is not an answer to a tool_result");

    assert!(matches!(error, TurnError::EndedMidToolUse), "got {error:?}");
}

/// The issue's own case (#190): the transcripts are identical, so the outcome's own field
/// is the only thing that can tell a cut-off answer from a whole one.
#[tokio::test]
async fn a_truncated_turn_is_told_from_a_finished_one() {
    let half = |reason| async move {
        let mut script = Script::new([vec![text("half a sen"), stop(reason)]]);
        run_turn(
            async |r| script.open(r).await,
            turn(&[], &[]),
            &ctx(SandboxPolicy::default()),
            |_| {},
            AllowAll,
        )
        .await
        .unwrap()
    };

    let cut = half(StopReason::MaxTokens).await;
    let whole = half(StopReason::EndTurn).await;

    assert_eq!(cut.messages, whole.messages, "the same transcript");
    assert_eq!(cut.stop, TurnStop::Answered);
    assert_eq!(whole.stop, TurnStop::Answered);
    assert_eq!(cut.round_stop, Some(StopReason::MaxTokens));
    assert_eq!(whole.round_stop, Some(StopReason::EndTurn));
}

/// A reported nothing, which `Unspecified` is, against a round that never reported — the
/// distinction the `Option` carries.
#[tokio::test]
async fn a_round_with_no_stop_reason_reports_unspecified() {
    let mut script = Script::new([vec![text("hi"), stop(StopReason::Unspecified)]]);

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[]),
        &ctx(SandboxPolicy::default()),
        |_| {},
        AllowAll,
    )
    .await
    .unwrap();

    assert_eq!(outcome.round_stop, Some(StopReason::Unspecified));
}

/// The other half of that distinction, and why `round_stop` is an `Option` rather than an
/// `Unspecified`: a cap of zero opens no stream at all, so there is no round to report on.
#[tokio::test]
async fn a_turn_that_ran_no_round_reports_no_stop() {
    let mut capped_at_none = turn(&[], &[]);
    capped_at_none.limits = TurnLimits {
        max_rounds: 0,
        ..TurnLimits::default()
    };
    let mut script = Script::new([]);

    let outcome = run_turn(
        async |r| script.open(r).await,
        capped_at_none,
        &ctx(SandboxPolicy::default()),
        |_| {},
        AllowAll,
    )
    .await
    .unwrap();

    assert!(script.sent.is_empty(), "it should not have asked at all");
    assert_eq!(outcome.stop, TurnStop::RoundLimit { rounds: 0 });
    assert_eq!(outcome.round_stop, None);
}

/// Both bounds at once, which is why the reason sits beside `stop` rather than inside
/// `TurnStop::Answered`; see `context/decision-round-limit-answer.md`.
#[tokio::test]
async fn a_capped_turn_names_both_bounds_it_hit() {
    let root = tempfile::tempdir().unwrap();
    let ctx = ctx(SandboxPolicy::default().allow_read(vetted(root.path())));
    let asking = |reason| {
        vec![
            call(
                "ls",
                serde_json::json!({ "path": root.path().to_str().unwrap() }),
            ),
            stop(reason),
        ]
    };
    let mut script = Script::new([
        asking(StopReason::ToolUse),
        asking(StopReason::ToolUse),
        asking(StopReason::MaxTokens),
    ]);

    let outcome = run_turn(
        async |r| script.open(r).await,
        capped_at_three(),
        &ctx,
        |_| {},
        AllowAll,
    )
    .await
    .unwrap();

    assert_eq!(outcome.stop, TurnStop::RoundLimit { rounds: 3 });
    assert_eq!(outcome.round_stop, Some(StopReason::MaxTokens));
}

/// A cut that outlived its round would make `agent-run` exit non-zero on a finished
/// answer. `usage`, three lines above it in the loop, keeps what a round did not report.
#[tokio::test]
async fn a_later_round_overwrites_an_earlier_cut() {
    let root = tempfile::tempdir().unwrap();
    let ctx = ctx(SandboxPolicy::default().allow_read(vetted(root.path())));
    let mut script = Script::new([
        vec![
            call(
                "ls",
                serde_json::json!({ "path": root.path().to_str().unwrap() }),
            ),
            // Cut part-way through asking, so the round that answers follows a cut one.
            stop(StopReason::MaxTokens),
        ],
        vec![text("one file"), stop(StopReason::EndTurn)],
    ]);

    let outcome = run_turn(
        async |r| script.open(r).await,
        capped_at_three(),
        &ctx,
        |_| {},
        AllowAll,
    )
    .await
    .unwrap();

    assert_eq!(script.sent.len(), 2, "the second round has to have run");
    assert_eq!(outcome.stop, TurnStop::Answered);
    assert_eq!(outcome.round_stop, Some(StopReason::EndTurn));
}

/// The negative of `a_tool_call_runs_without_a_stop_reason`: the reason is reported, and
/// still not acted on, so a provider mislabelling its own output buys no extra round.
#[tokio::test]
async fn a_tool_use_reason_with_no_call_still_answers() {
    let mut script = Script::new([vec![text("done"), stop(StopReason::ToolUse)]]);

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Ls]),
        &ctx(SandboxPolicy::default()),
        |_| {},
        AllowAll,
    )
    .await
    .unwrap();

    assert_eq!(script.sent.len(), 1, "it should not have re-entered");
    assert_eq!(outcome.stop, TurnStop::Answered);
    assert_eq!(outcome.round_stop, Some(StopReason::ToolUse));
}
