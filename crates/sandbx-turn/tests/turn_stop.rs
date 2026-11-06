//! Public contract of `run_turn_until`: what a stopped turn keeps.

use std::future::{self, Future};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, mpsc};
use std::task::Poll;
use std::time::Duration;

use futures_util::task::AtomicWaker;
use futures_util::{StreamExt, stream};
use sandbx_approval::{ApprovalDecision, CallGate, Settled, ToolCall};
use sandbx_core::SandboxPolicy;
use sandbx_event::{AgentEvent, StopReason};
use sandbx_prompt::{ContentBlock, RequestMessage, Role};
use sandbx_provider::EventStream;
use sandbx_tools::BuiltinTool;
use sandbx_turn::{Compaction, Turn, TurnLimits, TurnOutcome, TurnStop, run_turn_until};
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

/// A stop raised inside a tool call, landing before that call can finish (#497).
///
/// Raising a flag alone races the call: an `ls` that completes before its `JoinHandle` is
/// first polled resolves the round's answers in the poll that raised it, and `unless`
/// keeps the round. So [`Stop::raise`] first parks the runtime's only blocking thread on a
/// plug, which the call queues behind, and then wakes the task, whose next poll of `unless`
/// finds the stop first. The plug is released when the stop resolves, or when this drops.
#[derive(Default)]
struct Stop {
    flag: AtomicBool,
    waker: AtomicWaker,
    plug: Mutex<Option<mpsc::Sender<()>>>,
}

impl Stop {
    /// Resolves once the flag is set. Registers the waker, since nothing else re-polls the
    /// task while the plugged call is pending.
    fn raised(&self) -> impl Future<Output = ()> + '_ {
        future::poll_fn(|cx| {
            self.waker.register(cx.waker());
            if self.flag.load(Ordering::SeqCst) {
                self.plug
                    .lock()
                    .expect("held only to swap an Option")
                    .take();
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
    }

    /// Called from `approve`, so the plug is ahead in the blocking queue of the call
    /// `approve` is answering, which is spawned once it returns.
    fn raise(&self) {
        let (release, plugged) = mpsc::channel::<()>();
        tokio::task::spawn_blocking(move || plugged.recv());
        *self.plug.lock().expect("held only to swap an Option") = Some(release);

        self.flag.store(true, Ordering::SeqCst);
        self.waker.wake();
    }
}

/// Lets every call run, raises `stop` inside the `nth`, counting from one, and counts the
/// calls that finished.
struct RaisingOn<'a> {
    nth: usize,
    asked: usize,
    settled: usize,
    stop: &'a Stop,
}

impl CallGate for RaisingOn<'_> {
    fn approve(&mut self, _: ToolCall<'_>) -> ApprovalDecision {
        self.asked += 1;
        if self.asked == self.nth {
            self.stop.raise();
        }
        ApprovalDecision::Allow
    }

    fn settled(&mut self, _: Settled<'_>) {
        self.settled += 1;
    }
}

/// `turn` over `script`, with `root` readable, stopped inside its second `ls`.
///
/// On one blocking thread, which is what the plug holds. Under a timeout, since a stop
/// that is never polled leaves the plug in place and the call behind it pending forever.
/// Asserts the first call alone settled: the second finishing would mean the plug did not
/// hold it, and the race #497 describes is back.
fn stopped_in_second_call(script: &mut Script, turn: Turn<'_>, root: &Path) -> TurnOutcome {
    // Declared before `interrupt`, so a panic below drops the plug before the runtime,
    // whose drop waits for every blocking thread, the plugged one included.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        // `run_turn_until` arms a per-round timeout and panics without a timer.
        .enable_time()
        .build()
        .expect("a current-thread runtime");
    let interrupt = Stop::default();
    let mut gate = RaisingOn {
        nth: 2,
        asked: 0,
        settled: 0,
        stop: &interrupt,
    };

    let outcome = runtime
        .block_on(async {
            tokio::time::timeout(
                Duration::from_secs(30),
                run_turn_until(
                    async |r| script.open(r).await,
                    turn,
                    &ctx(SandboxPolicy::default().allow_read(vetted(root))),
                    |_| {},
                    &mut gate,
                    interrupt.raised(),
                ),
            )
            .await
        })
        .expect("the stop ended the turn")
        .expect("a scripted turn that only reads");

    assert_eq!(gate.settled, 1, "the stopped call finished before the stop");
    outcome
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

/// Round one alone: the stop drops the stopped call's answer, and the call is left to
/// finish rather than cancelled (#26).
#[test]
fn a_stop_mid_call_keeps_the_rounds_before_it() {
    let root = tempfile::tempdir().unwrap();
    let mut script = Script::new([
        listing(&root),
        listing(&root),
        vec![text("never asked"), stop(StopReason::EndTurn)],
    ]);

    let outcome = stopped_in_second_call(&mut script, turn(&[], &[BuiltinTool::Ls]), root.path());

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
#[test]
fn a_stopped_turn_returns_no_reasoning() {
    let root = tempfile::tempdir().unwrap();
    let mut thinking = vec![AgentEvent::ThinkingBlock {
        text: "weighing it up".to_string(),
        signature: "sig-1".to_string(),
    }];
    thinking.extend(listing(&root));
    let mut script = Script::new([thinking, listing(&root)]);

    let outcome = stopped_in_second_call(&mut script, turn(&[], &[BuiltinTool::Ls]), root.path());

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

/// A round's usage report, counting `input` tokens in.
fn measured(input: u32) -> AgentEvent {
    AgentEvent::Usage {
        input_tokens: Some(input),
        output_tokens: Some(1),
        cache_write_tokens: None,
        cache_read_tokens: None,
    }
}

/// The dropped round's request was the messages kept, so its figure is theirs.
#[test]
fn a_stop_mid_call_keeps_that_rounds_usage() {
    let root = tempfile::tempdir().unwrap();
    let mut first = listing(&root);
    first.insert(1, measured(500));
    let mut second = listing(&root);
    second.insert(1, measured(700));
    let mut script = Script::new([first, second]);

    let outcome = stopped_in_second_call(&mut script, turn(&[], &[BuiltinTool::Ls]), root.path());

    assert_eq!(outcome.stop, TurnStop::Interrupted);
    assert_eq!(outcome.usage.and_then(|u| u.input_tokens), Some(700));
}

/// Eight prose messages, a legal cut point at every even index.
fn conversation() -> Vec<RequestMessage> {
    (0..8)
        .map(|n| RequestMessage {
            role: if n % 2 == 0 {
                Role::User
            } else {
                Role::Assistant
            },
            content: vec![ContentBlock::Text {
                text: n.to_string(),
            }],
        })
        .collect()
}

/// Round two plans a deeper cut on round one's figure and is stopped before it reports, so
/// the cut handed back is round one's, the request that figure measured.
#[tokio::test(start_paused = true)]
async fn a_stop_mid_stream_keeps_the_cut_it_measured() {
    let root = tempfile::tempdir().unwrap();
    let history = conversation();
    let mut first = listing(&root);
    first.insert(1, measured(500));
    let mut rounds = [first].into_iter();
    let mut compacting = turn(&history, &[BuiltinTool::Ls]);
    compacting.limits.compaction = Some(Compaction {
        budget_tokens: 100,
        keep_recent: 2,
    });
    compacting.withheld = 2;
    let mut cuts = Vec::new();

    let outcome = run_turn_until(
        async |r| {
            cuts.push(r.messages.len());
            Ok(match rounds.next() {
                Some(events) => Box::pin(stream::iter(events.into_iter().map(Ok)).fuse()),
                None => stalled(),
            })
        },
        compacting,
        &ctx(SandboxPolicy::default().allow_read(vetted(root.path()))),
        |_| {},
        AllowAll,
        tokio::time::sleep(Duration::from_secs(1)),
    )
    .await
    .unwrap();

    // Not vacuous: round two did go out under a deeper cut than round one's.
    assert_eq!(cuts, [6, 4], "messages per request");
    assert_eq!(outcome.stop, TurnStop::Interrupted);
    assert_eq!(
        outcome.withheld, 2,
        "the cut round one's 500 was measured under"
    );
    assert_eq!(outcome.usage.and_then(|u| u.input_tokens), Some(500));
}

/// Stopped in its call, round two's request did finish streaming, so its cut is the one kept.
#[test]
fn a_stop_mid_call_keeps_the_cut_it_streamed() {
    let root = tempfile::tempdir().unwrap();
    let history = conversation();
    let mut first = listing(&root);
    first.insert(1, measured(500));
    let mut script = Script::new([first, listing(&root)]);
    let mut compacting = turn(&history, &[BuiltinTool::Ls]);
    compacting.limits.compaction = Some(Compaction {
        budget_tokens: 100,
        keep_recent: 2,
    });
    compacting.withheld = 2;

    let outcome = stopped_in_second_call(&mut script, compacting, root.path());

    assert_eq!(
        script.sent[1].messages.len(),
        4,
        "round two went out cut deeper"
    );
    assert_eq!(outcome.stop, TurnStop::Interrupted);
    assert_eq!(outcome.withheld, 6);
}
