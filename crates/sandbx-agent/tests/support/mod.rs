//! What both halves of the turn-loop suite drive `run_turn` with.
//!
//! Kept to the intersection the two share: `dead_code` is computed per test crate, so a
//! helper only one of them uses warns in the other, and belongs in that file instead.

use std::collections::VecDeque;

use sandbx_agent::{ApprovalDecision, ToolCall, Turn, TurnLimits};
use sandbx_core::SandboxPolicy;
use sandbx_providers::{
    AgentEvent, EventStream, MessagesRequest, ProviderError, RequestMessage, StopReason,
};
use sandbx_tools::{BuiltinTool, ExecutionContext};

/// Scripts one canned round per call, and records what was sent.
///
/// Not built on `sandbx-providers`' `MockProvider`: borrowing the one line it would
/// save costs a `mock` feature, a `required-features` test target and a CI command
/// naming both, and the recording has to live here anyway since it discards its own.
pub(crate) struct Script {
    rounds: VecDeque<Vec<AgentEvent>>,
    pub(crate) sent: Vec<MessagesRequest>,
}

impl Script {
    pub(crate) fn new(rounds: impl IntoIterator<Item = Vec<AgentEvent>>) -> Self {
        Self {
            rounds: rounds.into_iter().collect(),
            sent: Vec::new(),
        }
    }

    pub(crate) async fn open(
        &mut self,
        request: MessagesRequest,
    ) -> Result<EventStream, ProviderError> {
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

pub(crate) fn turn<'a>(history: &'a [RequestMessage], tools: &'a [BuiltinTool]) -> Turn<'a> {
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

pub(crate) fn ctx(policy: SandboxPolicy) -> ExecutionContext {
    ExecutionContext::new(policy)
}

/// A gate that refuses nothing, for the tests whose subject is not the gate.
///
/// The policy in `ctx` is what scopes those; this leaves the loop as it behaves when
/// every call is approved.
pub(crate) fn allow_all(_: ToolCall<'_>) -> ApprovalDecision {
    ApprovalDecision::Allow
}

pub(crate) fn text(delta: &str) -> AgentEvent {
    AgentEvent::Text {
        delta: delta.to_string(),
    }
}

pub(crate) fn stop(reason: StopReason) -> AgentEvent {
    AgentEvent::Stop { reason }
}

/// The id `call` uses, which is all a one-call round needs. A round scripting two gives
/// its own ids, so each result can be matched to the call it answers.
const CALL_ID: &str = "call_1";

pub(crate) fn call(name: &str, input: serde_json::Value) -> AgentEvent {
    AgentEvent::ToolCallRequested {
        id: CALL_ID.to_string(),
        name: name.to_string(),
        input,
    }
}

/// The rebuilt history in the only form `ContentBlock` can be compared in.
pub(crate) fn wire(messages: &[RequestMessage]) -> serde_json::Value {
    serde_json::to_value(messages).unwrap()
}
