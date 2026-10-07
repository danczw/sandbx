//! What both halves of the turn-loop suite drive `run_turn` with.
//!
//! Kept to the intersection the two share: `dead_code` is computed per test crate, so a
//! helper only one of them uses warns in the other.

use std::collections::VecDeque;

use sandbx_agent::{ApprovalDecision, CallGate, Settled, ToolCall, Turn, TurnLimits};
use sandbx_core::SandboxPolicy;
use sandbx_providers::{
    AgentEvent, EventStream, Prompt, ProviderError, RequestMessage, StopReason,
};
use sandbx_tools::{BuiltinTool, ExecutionContext};

/// Scripts one canned round per call, and records what was sent.
///
/// Not built on `sandbx-providers`' `MockProvider`, which would cost a `mock` feature, a
/// `required-features` target and a CI command naming both to borrow one line; see
/// `context/guide-turn-loop.md`.
pub(crate) struct Script {
    rounds: VecDeque<Vec<AgentEvent>>,
    pub(crate) sent: Vec<Prompt>,
}

impl Script {
    pub(crate) fn new(rounds: impl IntoIterator<Item = Vec<AgentEvent>>) -> Self {
        Self {
            rounds: rounds.into_iter().collect(),
            sent: Vec::new(),
        }
    }

    pub(crate) async fn open(&mut self, prompt: Prompt) -> Result<EventStream, ProviderError> {
        self.sent.push(prompt.clone());
        // Not `unwrap_or_default`: an empty round surfaces as `StreamEndedWithoutStop`,
        // so a miscounted script would fail with a misleading cause.
        let events = self
            .rounds
            .pop_front()
            .expect("the script was asked for more rounds than it holds");
        Ok(canned(events))
    }
}

/// An `EventStream` that replays `events` and then ends.
///
/// `fuse()` because `EventStream` promises a `FusedStream`: polling past the end must
/// not panic.
fn canned(events: Vec<AgentEvent>) -> EventStream {
    use futures_util::StreamExt;
    Box::pin(futures_util::stream::iter(events.into_iter().map(Ok)).fuse())
}

pub(crate) fn turn<'a>(history: &'a [RequestMessage], tools: &'a [BuiltinTool]) -> Turn<'a> {
    Turn {
        model: "claude-opus-5".to_string(),
        max_output_tokens: 1024,
        system: None,
        tools,
        tool_choice: None,
        thinking: None,
        history,
        limits: TurnLimits::default(),
        observed: None,
        withheld: 0,
    }
}

pub(crate) fn ctx(policy: SandboxPolicy) -> ExecutionContext {
    ExecutionContext::new(policy)
}

/// `path`, pinned to the object it names — the shape every grant takes (#212).
pub(crate) fn vetted(path: impl AsRef<std::path::Path>) -> sandbx_core::VettedPath {
    sandbx_core::VettedPath::vet(path).expect("an existing path to pin the grant to")
}

/// For the tests whose subject is not the gate: the policy in `ctx` scopes those.
pub(crate) struct AllowAll;

impl CallGate for AllowAll {
    fn approve(&mut self, _: ToolCall<'_>) -> ApprovalDecision {
        ApprovalDecision::Allow
    }

    fn settled(&mut self, _: Settled<'_>) {}
}

pub(crate) fn text(delta: &str) -> AgentEvent {
    AgentEvent::Text {
        delta: delta.to_string(),
    }
}

pub(crate) fn stop(reason: StopReason) -> AgentEvent {
    AgentEvent::Stop { reason }
}

/// All a one-call round needs; a round scripting two gives its own ids.
const CALL_ID: &str = "call_1";

pub(crate) fn call(name: &str, input: serde_json::Value) -> AgentEvent {
    AgentEvent::ToolCallRequested {
        id: CALL_ID.to_string(),
        name: name.to_string(),
        input,
    }
}
