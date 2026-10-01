//! Public contract of [`run_turn`]: what one streamed turn becomes.
//!
//! Every test drives the loop through the closure seam `run_turn` is generic
//! over, with `MockProvider` on the other side of it, so the whole suite runs
//! with no network access and no API key. Assertions on the rebuilt history go
//! through `serde_json::to_value`, because `ContentBlock` is `Serialize`-only and
//! has no `PartialEq` to compare against.

use std::collections::VecDeque;
use std::future::Future;

use sandbx_agent::{Turn, TurnError, run_turn};
use sandbx_providers::{
    AgentEvent, EventStream, MessagesRequest, MockProvider, ProviderError, RequestMessage, Role,
    StopReason,
};
use sandbx_tools::BuiltinTool;

/// Scripts one canned round per call, and records what was sent.
///
/// This is the seam itself. `run_turn` asks for a closure that opens a stream, so
/// a test hands it one that pops a canned round off the front. `MockProvider`
/// consuming `self` is exactly right here — each round gets a fresh one — which
/// is why driving a multi-round loop needs no change to `sandbx-providers`, and
/// why recording the requests can live in the test rather than in the double.
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

    /// Deliberately not an `async fn`: the future has to own everything it needs
    /// so `run_turn`'s single `Fut` type does not capture the `&mut self` borrow
    /// taken here. `+ use<>` is what states that, the same idiom
    /// `AnthropicClient::stream_chat` uses for the same reason.
    fn open(
        &mut self,
        request: MessagesRequest,
    ) -> impl Future<Output = Result<EventStream, ProviderError>> + use<> {
        self.sent.push(request.clone());
        let events = self.rounds.pop_front().unwrap_or_default();
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
    }
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

    let messages = run_turn(|r| script.open(r), turn(&[], &[]), |_| {})
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

    let messages = run_turn(|r| script.open(r), turn(&[], &[]), |_| {})
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

    let error = run_turn(|r| script.open(r), turn(&[], &[]), |_| {})
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
