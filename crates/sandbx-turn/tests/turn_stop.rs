//! Public contract of `run_turn_until`: what a stopped turn keeps.

use std::future::{self, Future};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

use futures_util::{StreamExt, stream};
use sandbx_approval::{ApprovalDecision, CallGate, Settled, ToolCall};
use sandbx_core::SandboxPolicy;
use sandbx_event::{AgentEvent, StopReason};
use sandbx_prompt::{ContentBlock, Role};
use sandbx_provider::EventStream;
use sandbx_tools::BuiltinTool;
use sandbx_turn::{TurnLimits, TurnStop, run_turn_until};
use sandbx_turn_fixture::{AllowAll, Script, call, ctx, stop, text, turn, vetted};

/// A round asking for one `ls` of `root`.
fn listing(root: &tempfile::TempDir) -> Vec<AgentEvent> {
    vec![
        call(
            "ls",
            serde_json::json!({ "path": root.path().to_str().expect("a temp path is UTF-8") }),
        ),
        stop(StopReason::ToolUse),
    ]
}

/// Resolves once `raised` is set. Registers no waker: the round it races is what wakes the
/// task, and `unless` polls the stop first when it does.
fn raised(flag: &AtomicBool) -> impl Future<Output = ()> + '_ {
    future::poll_fn(|_| {
        if flag.load(Ordering::SeqCst) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
}

/// Lets every call run, and raises `stop` as it lets through the `nth`, counting from one.
struct RaisingOn<'a> {
    nth: usize,
    asked: AtomicUsize,
    stop: &'a AtomicBool,
}

impl CallGate for RaisingOn<'_> {
    fn approve(&mut self, _: ToolCall<'_>) -> ApprovalDecision {
        if self.asked.fetch_add(1, Ordering::SeqCst) + 1 == self.nth {
            self.stop.store(true, Ordering::SeqCst);
        }
        ApprovalDecision::Allow
    }

    fn settled(&mut self, _: Settled<'_>) {}
}

#[tokio::test]
async fn a_stop_already_resolved_sends_nothing() {
    let mut script = Script::new([vec![text("never asked"), stop(StopReason::EndTurn)]]);

    let outcome = run_turn_until(
        async |r| script.open(r).await,
        turn(&[], &[]),
        &ctx(SandboxPolicy::default()),
        |_| {},
        AllowAll,
        future::ready(()),
    )
    .await
    .unwrap();

    assert_eq!(outcome.stop, TurnStop::Interrupted);
    assert!(outcome.messages.is_empty(), "got {:?}", outcome.messages);
    assert!(script.sent.is_empty(), "a request went out after the stop");
}

/// The tool still ran: the stop drops its answer, not the call (#26).
#[tokio::test]
async fn a_stop_mid_call_keeps_the_rounds_before_it() {
    let root = tempfile::tempdir().unwrap();
    let flag = AtomicBool::new(false);
    let mut script = Script::new([
        listing(&root),
        listing(&root),
        vec![text("never asked"), stop(StopReason::EndTurn)],
    ]);

    let outcome = run_turn_until(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Ls]),
        &ctx(SandboxPolicy::default().allow_read(vetted(root.path()))),
        |_| {},
        RaisingOn {
            nth: 2,
            asked: AtomicUsize::new(0),
            stop: &flag,
        },
        raised(&flag),
    )
    .await
    .unwrap();

    assert_eq!(outcome.stop, TurnStop::Interrupted);
    let roles: Vec<Role> = outcome.messages.iter().map(|m| m.role).collect();
    assert_eq!(roles, [Role::Assistant, Role::User], "round one alone");
    assert!(
        matches!(
            outcome.messages[1].content[..],
            [ContentBlock::ToolResult { .. }]
        ),
        "got {:?}",
        outcome.messages
    );
    assert_eq!(script.sent.len(), 2, "no third request after the stop");
}

/// A round that streams forever: only the stop can end it under a 300-second bound.
fn stalled() -> EventStream {
    Box::pin(stream::pending())
}

/// Paused time, so the sleep standing in for a keypress fires as soon as the runtime idles.
#[tokio::test(start_paused = true)]
async fn a_stop_mid_stream_drops_that_round_alone() {
    let root = tempfile::tempdir().unwrap();
    let mut rounds = [listing(&root)].into_iter();
    let mut capped = turn(&[], &[BuiltinTool::Ls]);
    capped.limits = TurnLimits {
        stream_timeout: Duration::from_secs(300),
        ..TurnLimits::default()
    };
    let mut opened = 0;

    let outcome = run_turn_until(
        async |_| {
            opened += 1;
            Ok(match rounds.next() {
                Some(events) => Box::pin(stream::iter(events.into_iter().map(Ok)).fuse()),
                None => stalled(),
            })
        },
        capped,
        &ctx(SandboxPolicy::default().allow_read(vetted(root.path()))),
        |_| {},
        AllowAll,
        tokio::time::sleep(Duration::from_secs(1)),
    )
    .await
    .unwrap();

    assert_eq!(outcome.stop, TurnStop::Interrupted);
    assert_eq!(opened, 2, "the stop landed in round two's stream");
    assert_eq!(outcome.messages.len(), 2, "got {:?}", outcome.messages);
}

/// The interrupted exit goes through the same strip as every other.
#[tokio::test]
async fn a_stopped_turn_returns_no_reasoning() {
    let root = tempfile::tempdir().unwrap();
    let flag = AtomicBool::new(false);
    let mut thinking = vec![AgentEvent::ThinkingBlock {
        text: "weighing it up".to_string(),
        signature: "sig-1".to_string(),
    }];
    thinking.extend(listing(&root));
    let mut script = Script::new([thinking, listing(&root)]);

    let outcome = run_turn_until(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Ls]),
        &ctx(SandboxPolicy::default().allow_read(vetted(root.path()))),
        |_| {},
        RaisingOn {
            nth: 2,
            asked: AtomicUsize::new(0),
            stop: &flag,
        },
        raised(&flag),
    )
    .await
    .unwrap();

    assert_eq!(outcome.stop, TurnStop::Interrupted);
    assert_eq!(outcome.messages.len(), 2, "got {:?}", outcome.messages);
    assert!(
        !outcome
            .messages
            .iter()
            .flat_map(|message| &message.content)
            .any(ContentBlock::is_thinking),
        "got {:?}",
        outcome.messages
    );
}
