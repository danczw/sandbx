//! What every part of the turn-loop suite drives `run_turn` with.
//!
//! A dev-dependency only: nothing links this into a build that ships.
//!
//! The alternative is what this replaces — `sandbx-turn/tests/support/mod.rs`, declared
//! `mod support;` by each of three roots in the same package, which worked. Two things
//! make a crate better. A test root declaring a non-test submodule is what #333 set out
//! to end, the `mod` line being indistinguishable from one naming a test file. And
//! `dead_code` is per test target, so every item had to sit in the intersection all
//! three roots use or warn in the ones that did not. Compiled once with a public
//! surface, that constraint is gone, at a price set out further down.
//!
//! A `#[cfg(feature = ..)]` export from `sandbx-turn` would have kept one package at the
//! price of a surface that diverges between builds — on in the rlib `--all-targets`
//! builds, off in the release build — so production code naming the fixture would pass
//! clippy and the whole suite and fail first at release. `context/guide-ci.md` records
//! that for a *self* dev-dependency; feature unification makes this case the same one.
//!
//! The cost is that every item is `pub` and so under `missing_docs`, that the crate is
//! compiled by the default `cargo test`, `clippy --all-targets` and `doc` runs, and —
//! the one that is not a gain — that nothing warns when an item goes unused. Per-target
//! `dead_code` was noise three times over, but it was also the only signal that *every*
//! root had stopped calling something; a cross-crate `pub` item warns nowhere, so a dead
//! helper here compiles forever and only `public-api.txt` records that it exists.
//!
//! **The dependency cycle is deliberate.** This crate depends on `sandbx-turn` while
//! `sandbx-turn` dev-depends on it. Cargo permits that because the cycle never exists in
//! the unit graph: `sandbx-turn`'s *test* targets link this crate, which links
//! `sandbx-turn`'s *lib*. `tokio` ↔ `tokio-test` is the published precedent. The
//! alternative — dropping [`turn`], the only item needing `sandbx-turn`, and copying the
//! `Turn` literal into all three roots — is the duplication this crate exists to remove.

use std::collections::VecDeque;
use std::path::Path;

use sandbx_approval::{ApprovalDecision, CallGate, Settled, ToolCall};
use sandbx_core::SandboxPolicy;
use sandbx_event::{AgentEvent, StopReason};
use sandbx_prompt::{Prompt, RequestMessage};
use sandbx_provider::{EventStream, ProviderError};
use sandbx_tools::{BuiltinTool, ExecutionContext};
use sandbx_turn::{Turn, TurnLimits};

/// Scripts one canned round per call, and records what was sent.
pub struct Script {
    rounds: VecDeque<Vec<AgentEvent>>,

    /// Every [`Prompt`] [`open`](Self::open) was asked for, in order — which is how a
    /// test asserts what a round actually sent rather than what it meant to.
    pub sent: Vec<Prompt>,
}

impl Script {
    /// One entry per round, replayed in order.
    pub fn new(rounds: impl IntoIterator<Item = Vec<AgentEvent>>) -> Self {
        Self {
            rounds: rounds.into_iter().collect(),
            sent: Vec::new(),
        }
    }

    /// Record `prompt` and hand back the next round's events, in the shape `run_turn`'s
    /// closure seam wants. Panics when the script is exhausted, since a test asking for
    /// a round it never wrote is a bug in the test.
    pub async fn open(&mut self, prompt: Prompt) -> Result<EventStream, ProviderError> {
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

/// A [`Turn`] over `history` and `tools`, with every other field at a fixed default so a
/// test varies only what it is about.
pub fn turn<'a>(history: &'a [RequestMessage], tools: &'a [BuiltinTool]) -> Turn<'a> {
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

/// The context a scripted turn runs its calls in. `policy` is the whole of what confines
/// them, which is why the gate-less tests pass [`AllowAll`].
pub fn ctx(policy: SandboxPolicy) -> ExecutionContext {
    ExecutionContext::new(policy)
}

/// `path`, pinned to the object it names — the shape every grant takes (#212).
pub fn vetted(path: impl AsRef<Path>) -> sandbx_core::VettedPath {
    sandbx_core::VettedPath::vet(path).expect("an existing path to pin the grant to")
}

/// For the tests whose subject is not the gate: the policy in [`ctx`] scopes those.
pub struct AllowAll;

impl CallGate for AllowAll {
    fn approve(&mut self, _: ToolCall<'_>) -> ApprovalDecision {
        ApprovalDecision::Allow
    }

    fn settled(&mut self, _: Settled<'_>) {}
}

/// One `Text` delta, the model's own channel.
pub fn text(delta: &str) -> AgentEvent {
    AgentEvent::Text {
        delta: delta.to_string(),
    }
}

/// The event that closes a round, carrying why it ended.
pub fn stop(reason: StopReason) -> AgentEvent {
    AgentEvent::Stop { reason }
}

/// All a one-call round needs; a round scripting two gives its own ids.
const CALL_ID: &str = "call_1";

/// A requested call on `name` with `input`, under the one shared id.
pub fn call(name: &str, input: serde_json::Value) -> AgentEvent {
    AgentEvent::ToolCallRequested {
        id: CALL_ID.to_string(),
        name: name.to_string(),
        input,
    }
}
