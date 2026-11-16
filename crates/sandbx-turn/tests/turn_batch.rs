//! Public contract of `run_turn` for a round of several calls: which run together, and
//! in what order the gate and the model hear about them (#242).
// `mkfifo` is spawned to build a fixture: std cannot create a named pipe. Not code
// escaping the sandbox, which is what the ban on `Command::new` exists to stop.
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use std::{fs, thread};

use sandbx_approval::{ApprovalDecision, CallGate, Settled, ToolCall};
use sandbx_core::SandboxPolicy;
use sandbx_event::{AgentEvent, StopReason};
use sandbx_prompt::{ContentBlock, RequestMessage};
use sandbx_tools::BuiltinTool;
use sandbx_turn::{TurnStop, run_turn, run_turn_until};
use sandbx_turn_fixture::{AllowAll, Script, ctx, stop, text, turn, vetted};

/// A gate that allows everything and logs `ask:{name}` and `settle:{name}` as they happen,
/// so the interleaving of the two is the assertion.
#[derive(Default)]
struct Logged(Vec<String>);

impl CallGate for Logged {
    fn approve(&mut self, call: ToolCall<'_>) -> ApprovalDecision {
        self.0.push(format!("ask:{}", call.tool.name()));
        ApprovalDecision::Allow
    }

    fn settled(&mut self, call: Settled<'_>) {
        self.0.push(format!("settle:{}", call.name));
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

fn path_of(path: &Path) -> serde_json::Value {
    serde_json::json!({ "path": path.to_str().expect("a temp path is UTF-8") })
}

fn mkfifo(path: &Path) {
    let made = Command::new("mkfifo")
        .arg(path)
        .status()
        .expect("mkfifo should run");
    assert!(made.success(), "the fixture needs a named pipe at {path:?}");
}

/// The `(tool_use_id, content)` of each `tool_result` in a user turn, in order.
fn answers(message: &RequestMessage) -> Vec<(&str, &str)> {
    message
        .content
        .iter()
        .map(|block| match block {
            ContentBlock::ToolResult {
                tool_use_id,
                content,
                ..
            } => (tool_use_id.as_str(), content.as_str()),
            other => panic!("not a tool_result: {other:?}"),
        })
        .collect()
}

/// Writes `b` and then `a`, each into the FIFO of that name, on a thread of its own.
///
/// A writer's `open` waits for a reader, so this finishes only if `read a` and `read b` are
/// both open at once. Dropped, it holds both FIFOs open read-write while it joins the
/// writer, which unparks every side of a run that never overlapped: the `read` left on
/// `a` sees a writer, the writer sees a reader, and the runtime's drop is not left waiting.
struct Writer {
    fifos: [PathBuf; 2],
    thread: Option<thread::JoinHandle<()>>,
}

impl Writer {
    fn b_then_a(a: PathBuf, b: PathBuf) -> Self {
        let order = [b.clone(), a.clone()];
        let thread = thread::spawn(move || {
            for fifo in order {
                let name = fifo.file_name().expect("a FIFO this test named").to_owned();
                if let Ok(mut pipe) = fs::OpenOptions::new().write(true).open(&fifo) {
                    let _ = std::io::Write::write_all(&mut pipe, name.as_encoded_bytes());
                }
            }
        });
        Self {
            fifos: [a, b],
            thread: Some(thread),
        }
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        let held: Vec<_> = self
            .fifos
            .iter()
            .filter_map(|fifo| {
                fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(fifo)
                    .ok()
            })
            .collect();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        drop(held);
    }
}

/// Run one after the other, `read a` waits in `open` for a writer that is itself waiting
/// on `b`, so only a round whose reads overlap ends before the bound.
#[tokio::test]
async fn reads_in_one_round_run_together() {
    let root = tempfile::tempdir().unwrap();
    let (a, b) = (root.path().join("a"), root.path().join("b"));
    mkfifo(&a);
    mkfifo(&b);
    let mut script = Script::new([
        vec![
            call_id("first", "read", path_of(&a)),
            call_id("second", "read", path_of(&b)),
            stop(StopReason::ToolUse),
        ],
        vec![text("Read both."), stop(StopReason::EndTurn)],
    ]);
    // After `root`, so it is dropped first: with the FIFOs unlinked its release would fail.
    let _writer = Writer::b_then_a(a.clone(), b.clone());

    let outcome = tokio::time::timeout(
        Duration::from_secs(5),
        run_turn(
            async |r| script.open(r).await,
            turn(&[], &[BuiltinTool::Read]),
            &ctx(SandboxPolicy::default().allow_read(vetted(root.path()))),
            |_| {},
            AllowAll,
        ),
    )
    .await
    .expect("two reads in one round ran one at a time, so `read a` never got its writer")
    .unwrap();

    assert_eq!(
        answers(&outcome.messages[1]),
        [("first", "a"), ("second", "b")],
        "results are in the order asked, not the order `b` and `a` were written"
    );
}

/// A `write` is asked about only once the reads before it have settled: nothing is in
/// flight while the gate decides, which is what lets `--approve call` block on `/dev/tty`.
#[tokio::test]
async fn a_write_waits_for_the_reads_before_it() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("note.txt");
    fs::write(&file, "before").unwrap();
    let mut script = Script::new([
        vec![
            call_id("read", "read", path_of(&file)),
            call_id("ls", "ls", path_of(root.path())),
            call_id(
                "write",
                "write",
                serde_json::json!({ "path": file.to_str().unwrap(), "content": "after" }),
            ),
            call_id("again", "read", path_of(&file)),
            stop(StopReason::ToolUse),
        ],
        vec![text("Done."), stop(StopReason::EndTurn)],
    ]);
    let mut gate = Logged::default();

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn(
            &[],
            &[BuiltinTool::Read, BuiltinTool::Ls, BuiltinTool::Write],
        ),
        &ctx(SandboxPolicy::default()
            .allow_read(vetted(root.path()))
            .allow_write(vetted(root.path()))),
        |_| {},
        &mut gate,
    )
    .await
    .unwrap();

    assert_eq!(
        gate.0,
        [
            "ask:read",
            "ask:ls",
            "settle:read",
            "settle:ls",
            "ask:write",
            "settle:write",
            "ask:read",
            "settle:read",
        ],
        "the reads are asked together, and the write is a barrier on both sides"
    );
    let results = answers(&outcome.messages[1]);
    assert_eq!(
        results[0],
        ("read", "before"),
        "the first read ran before the write"
    );
    assert_eq!(results[3], ("again", "after"), "the last read ran after it");
}

/// A refusal between two reads settles in its place, not ahead of the reads it sits among:
/// the operator's lines and the model's results read in the order the model asked.
#[tokio::test]
async fn results_and_settles_keep_the_order_asked() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("note.txt");
    fs::write(&file, "text").unwrap();
    let mut script = Script::new([
        vec![
            call_id("one", "read", path_of(&file)),
            call_id("two", "rm", serde_json::json!({})),
            call_id("three", "read", path_of(&file)),
            stop(StopReason::ToolUse),
        ],
        vec![text("Done."), stop(StopReason::EndTurn)],
    ]);
    let mut gate = Logged::default();

    let outcome = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Read]),
        &ctx(SandboxPolicy::default().allow_read(vetted(root.path()))),
        |_| {},
        &mut gate,
    )
    .await
    .unwrap();

    assert_eq!(
        gate.0,
        [
            "ask:read",
            "ask:read",
            "settle:read",
            "settle:rm",
            "settle:read"
        ],
        "an unknown name never reaches `approve`, and settles between the reads around it"
    );
    let ids: Vec<_> = answers(&outcome.messages[1])
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    assert_eq!(
        ids,
        ["one", "two", "three"],
        "one result per call, in order"
    );
}

/// A stop that lands while the reads ahead of a `write` run ends the round there: the
/// operator is never asked about a call behind the stop, and it is answered as not run.
#[tokio::test]
async fn a_stop_during_the_reads_skips_the_write() {
    let root = tempfile::tempdir().unwrap();
    let (fifo, unread) = (root.path().join("a"), root.path().join("b"));
    mkfifo(&fifo);
    mkfifo(&unread);
    let target = root.path().join("note.txt");
    let mut script = Script::new([
        vec![
            call_id("read", "read", path_of(&fifo)),
            call_id(
                "write",
                "write",
                serde_json::json!({ "path": target.to_str().unwrap(), "content": "late" }),
            ),
            stop(StopReason::ToolUse),
        ],
        vec![text("never asked"), stop(StopReason::EndTurn)],
    ]);
    // Nothing reads `b`, so `a` gets no writer until the drop frees the parked `read`.
    let _writer = Writer::b_then_a(fifo.clone(), unread.clone());
    let mut gate = Logged::default();

    let outcome = run_turn_until(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Read, BuiltinTool::Write]),
        &ctx(SandboxPolicy::default()
            .allow_read(vetted(root.path()))
            .allow_write(vetted(root.path()))),
        |_| {},
        &mut gate,
        tokio::time::sleep(Duration::from_millis(200)),
    )
    .await
    .unwrap();

    assert_eq!(outcome.stop, TurnStop::Interrupted);
    assert_eq!(
        gate.0,
        ["ask:read", "settle:read"],
        "the write behind the stop was put to the gate"
    );
    assert!(!target.exists(), "a write behind the stop ran");
    let results = answers(&outcome.messages[1]);
    assert!(
        results[1].1.starts_with("not run"),
        "the write is answered as never run, got {results:?}"
    );
}
