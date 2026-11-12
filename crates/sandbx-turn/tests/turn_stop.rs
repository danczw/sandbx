//! Public contract of `run_turn_until`: what a stopped turn keeps.
// `mkfifo` is spawned to build a fixture: std cannot create a named pipe. Not code
// escaping the sandbox, which is what the ban on `Command::new` exists to stop.
#![allow(clippy::disallowed_methods)]

use std::future::{self, Future};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, mpsc};
use std::task::Poll;
use std::time::{Duration, Instant};
use std::{fs, thread};

use futures_util::task::AtomicWaker;
use futures_util::{StreamExt, stream};
use sandbx_approval::{ApprovalDecision, CallGate, Settled, ToolCall};
use sandbx_core::SandboxPolicy;
use sandbx_event::{AgentEvent, StopReason};
use sandbx_prompt::{ContentBlock, RequestMessage, Role};
use sandbx_provider::EventStream;
use sandbx_tools::{BuiltinTool, ExecutionContext};
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

/// Opens `fifo` for writing once `delay` has passed, which wakes a reader parked on it, and
/// joins that thread when dropped.
struct Release(Option<thread::JoinHandle<()>>);

impl Release {
    fn after(delay: Duration, fifo: std::path::PathBuf) -> Self {
        Self(Some(thread::spawn(move || {
            thread::sleep(delay);
            let _ = fs::OpenOptions::new().write(true).open(fifo);
        })))
    }
}

impl Drop for Release {
    fn drop(&mut self) {
        if let Some(thread) = self.0.take() {
            let _ = thread.join();
        }
    }
}

/// The `(content, is_error)` of each `tool_result` in a user turn.
fn answers(message: &RequestMessage) -> Vec<(&str, Option<bool>)> {
    message
        .content
        .iter()
        .map(|block| match block {
            ContentBlock::ToolResult {
                content, is_error, ..
            } => (content.as_str(), *is_error),
            other => panic!("not a tool_result: {other:?}"),
        })
        .collect()
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

/// What a stopped turn handed back, and what its gate saw of the calls.
struct Stopped {
    outcome: TurnOutcome,
    asked: usize,
    settled: usize,
}

/// `turn` over `script`, with `root` readable, stopped inside its second `ls`.
///
/// Asserts the stopped call settled, which is the whole of what the stop owes it: the
/// call is waited for rather than left to finish unseen (#26).
fn stopped_in_second_call(script: &mut Script, turn: Turn<'_>, root: &Path) -> TurnOutcome {
    let stopped = stopped_in_second_call_under(
        script,
        turn,
        &ctx(SandboxPolicy::default().allow_read(vetted(root))),
    );

    assert_eq!(stopped.settled, 2, "the stopped call was not waited for");
    stopped.outcome
}

/// `turn` over `script`, stopped inside the second call its gate is asked about.
///
/// On one blocking thread, which is what the plug holds. Under a timeout, since a stop
/// that is never polled leaves the plug in place and the call behind it pending forever.
/// The plug is what keeps the second call from finishing before the stop lands: without
/// it the race #497 describes is back, and the call settles on its own.
fn stopped_in_second_call_under(
    script: &mut Script,
    turn: Turn<'_>,
    ctx: &ExecutionContext,
) -> Stopped {
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
                    ctx,
                    |_| {},
                    &mut gate,
                    interrupt.raised(),
                ),
            )
            .await
        })
        .expect("the stop ended the turn")
        .expect("a scripted turn that only reads");

    Stopped {
        outcome,
        asked: gate.asked,
        settled: gate.settled,
    }
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

/// The stop reaches a round that has more calls behind the stopped one: the stopped call
/// is waited for and settles, and nothing behind it is put to the gate or run (#26). The
/// stopped call is a `write`, which is always waited for and lands; a read-only call is
/// abandoned instead, so it could settle either way.
///
/// The round is kept with every call answered: the one that finished before the stop says
/// what it found, the stopped one says only that it finished, and the one behind it says it
/// did not run.
#[test]
fn a_stop_mid_call_starts_no_call_behind_it() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("seen.txt"), "").unwrap();
    let landed = root.path().join("landed.txt");
    let behind = root.path().join("behind.txt");
    let ctx = ctx(SandboxPolicy::default()
        .allow_read(vetted(root.path()))
        .allow_write(vetted(root.path())));
    let listed = serde_json::json!({ "path": root.path().to_str().unwrap() });
    let mut script = Script::new([
        vec![
            call("ls", listed),
            call(
                "write",
                serde_json::json!({ "path": landed.to_str().unwrap(), "content": "landed" }),
            ),
            call(
                "write",
                serde_json::json!({ "path": behind.to_str().unwrap(), "content": "behind it" }),
            ),
            stop(StopReason::ToolUse),
        ],
        vec![text("never asked"), stop(StopReason::EndTurn)],
    ]);

    let stopped = stopped_in_second_call_under(
        &mut script,
        turn(&[], &[BuiltinTool::Ls, BuiltinTool::Write]),
        &ctx,
    );

    assert_eq!(stopped.outcome.stop, TurnStop::Interrupted);
    assert_eq!(stopped.settled, 2, "the stopped call was not waited for");
    assert_eq!(stopped.asked, 2, "a call behind the stop reached the gate");
    assert_eq!(fs::read_to_string(&landed).unwrap(), "landed");
    assert!(!behind.exists(), "a call behind the stop ran");

    let [assistant, user] = &stopped.outcome.messages[..] else {
        panic!(
            "expected the stopped round, got {:?}",
            stopped.outcome.messages
        );
    };
    assert_eq!(assistant.role, Role::Assistant);
    let [before, during, after] = &answers(user)[..] else {
        panic!("a result for each of three calls, got {user:?}");
    };
    assert!(before.0.contains("seen.txt"), "got {before:?}");
    assert_eq!(before.1, None);
    // What the operator stopped before reading, and a resume would send on.
    assert!(during.0.contains("withheld"), "got {during:?}");
    assert!(
        !during.0.contains("landed"),
        "the write's own report got through: {during:?}"
    );
    assert_eq!(during.1, Some(true));
    assert!(after.0.contains("not run"), "got {after:?}");
    assert_eq!(after.1, Some(true));
}

/// Round one answered, the stop in round two's only call: both rounds are kept (#26).
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
    assert_eq!(
        roles,
        [Role::Assistant, Role::User, Role::Assistant, Role::User]
    );
    // An `ls` is abandoned or finished, whichever the poll finds first: either says nothing of
    // what it listed.
    let last = answers(&outcome.messages[3]);
    assert_eq!(last.len(), 1, "got {:?}", outcome.messages);
    assert_eq!(last[0].1, Some(true), "got {last:?}");
    assert!(
        last[0].0.contains("withheld") || last[0].0.contains("cancelled"),
        "got {last:?}"
    );
    assert_eq!(script.sent.len(), 2, "no third request after the stop");
}

/// A `read` of a FIFO with no writer waits in `open` for as long as it takes someone to
/// write, which no stop can interrupt. It is read-only and writes nothing, so the stop
/// abandons it instead of waiting (#26).
#[tokio::test]
async fn a_stop_does_not_wait_for_a_read_that_cannot_finish() {
    let root = tempfile::tempdir().unwrap();
    let fifo = root.path().join("pipe");
    let made = Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo should run");
    assert!(made.success());
    let mut script = Script::new([
        vec![
            call(
                "read",
                serde_json::json!({ "path": fifo.to_str().unwrap() }),
            ),
            stop(StopReason::ToolUse),
        ],
        vec![text("never asked"), stop(StopReason::EndTurn)],
    ]);
    // Frees the thread the read is parked on after two seconds, a stop that waits for it
    // then failing the bound below instead of hanging the runtime's drop. Declared after
    // `root`, so it is joined before the directory goes: with the FIFO unlinked the open
    // fails, and the read stays parked.
    let _release = Release::after(Duration::from_secs(2), fifo.clone());
    let started = Instant::now();

    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        run_turn_until(
            async |r| script.open(r).await,
            turn(&[], &[BuiltinTool::Read]),
            &ctx(SandboxPolicy::default().allow_read(vetted(root.path()))),
            |_| {},
            AllowAll,
            tokio::time::sleep(Duration::from_millis(200)),
        ),
    )
    .await
    .expect("the stop ended the turn")
    .unwrap();
    let elapsed = started.elapsed();

    assert_eq!(outcome.stop, TurnStop::Interrupted);
    assert!(
        elapsed < Duration::from_secs(1),
        "the stop waited {elapsed:?} for a read"
    );
    let [_, user] = &outcome.messages[..] else {
        panic!("expected the stopped round, got {:?}", outcome.messages);
    };
    let [result] = &answers(user)[..] else {
        panic!("a result for the one call, got {user:?}");
    };
    assert!(result.0.contains("cancelled"), "got {result:?}");
    assert_eq!(result.1, Some(true));
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
    assert_eq!(outcome.messages.len(), 4, "got {:?}", outcome.messages);
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
