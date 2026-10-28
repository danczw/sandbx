//! What a tool's own filesystem work puts on the audit trail.
//!
//! `sandbx-core`'s suite covers each `FsGuard` entry point. What it cannot see is a tool
//! reaching the filesystem beside the guard, which leaves no record at all — so the
//! assertions here are about the tool, not the guard.

use std::sync::{Arc, Mutex};

use sandbx_core::{AUDIT_TARGET, SandboxPolicy, VettedPath};
use sandbx_tools::{BuiltinTool, ExecutionContext};
use serde_json::json;
use tracing::subscriber::with_default;
use tracing_subscriber::layer::SubscriberExt;

/// `path`, pinned to the object it names — the shape every grant takes (#212).
fn vetted(path: impl AsRef<std::path::Path>) -> VettedPath {
    VettedPath::vet(path).expect("an existing path to pin the grant to")
}

/// Collects audit events so a test can assert on what was recorded.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<String>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Captured {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if event.metadata().target() != AUDIT_TARGET {
            return;
        }
        let mut visitor = Collect(String::new());
        event.record(&mut visitor);
        self.0.lock().unwrap().push(visitor.0);
    }
}

struct Collect(String);

impl tracing::field::Visit for Collect {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push_str(&format!("{}={value:?} ", field.name()));
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.push_str(&format!("{}={value} ", field.name()));
    }
}

fn capture(f: impl FnOnce()) -> Vec<String> {
    let sink = Captured::default();
    let subscriber = tracing_subscriber::registry().with(sink.clone());
    with_default(subscriber, f);
    sink.0.lock().unwrap().clone()
}

/// One byte past `MAX_FILE_BYTES`, which is 2 MiB in `grep` and not a knob.
const OVER_THE_CAP: usize = 2 * 1024 * 1024 + 1;

/// `grep` read nothing of this one, and measuring it by opening is what the trail sees (#275).
#[test]
fn the_file_grep_only_measures_is_still_an_access() {
    let root = tempfile::tempdir().unwrap();
    let big = root.path().join("big.txt");
    let small = root.path().join("small.txt");
    std::fs::write(&big, "x".repeat(OVER_THE_CAP)).unwrap();
    std::fs::write(&small, b"needle\n").unwrap();
    let ctx = ExecutionContext::new(SandboxPolicy::default().allow_read(vetted(root.path())));

    let lines = capture(|| {
        BuiltinTool::Grep
            .execute(
                json!({ "path": root.path().to_str().unwrap(), "pattern": "needle" }),
                &ctx,
            )
            .unwrap();
    });

    let allowed = |path: &std::path::Path| {
        lines.iter().any(|line| {
            line.contains("decision=allowed") && line.contains(&path.display().to_string())
        })
    };

    assert!(allowed(&big), "the oversized file is unrecorded: {lines:?}");
    // The positive control: without it, a walk that visited nothing would also have no
    // record of `big` and pass for the opposite reason.
    assert!(allowed(&small), "the walk read nothing at all: {lines:?}");
}

/// The session id this context names, as every spawn through it must record.
const SESSION: &str = "abc123";

/// A context whose spawns fail to start: the helper does not exist, so the pair is a
/// `spawned` and a `failed` with no kernel and no command ever executed.
fn spawning_ctx() -> ExecutionContext {
    ExecutionContext::new(SandboxPolicy::default())
        .with_session(SESSION)
        .with_helper("/nonexistent/helper")
}

/// Run `command` under `ctx`, discarding the refusal the absent helper returns.
fn bash(command: &str, ctx: &ExecutionContext) {
    let _ = BuiltinTool::Bash.execute(json!({ "command": command }), ctx);
}

/// `with_session` to `ExecutionContext` to `SandboxedCommand` to the record, which is the
/// whole of the plumbing #249 added — and `program` is `/bin/sh` for every `bash` call, so
/// without `args` the command itself is on no record at all.
#[test]
fn a_bash_spawn_records_the_session_and_the_command() {
    let lines = capture(|| bash("echo hi", &spawning_ctx()));

    assert_eq!(lines.len(), 2, "a spawn and its outcome, got: {lines:?}");
    for line in &lines {
        assert!(
            line.contains(&format!("session={SESSION} ")),
            "a record did not name the session its context held: {line}"
        );
    }

    let spawned = lines
        .iter()
        .find(|line| line.contains("decision=spawned"))
        .unwrap_or_else(|| panic!("no spawn was recorded: {lines:?}"));

    // Both on one record: `program` and `args` are adjacent `&str` parameters, so a
    // transposition compiles and reads plausibly.
    assert!(spawned.contains("program=/bin/sh"), "got: {spawned}");
    assert!(
        spawned.contains(r#"args=["-c", "echo hi"]"#),
        "the trail carries `/bin/sh` and not what it was asked to run: {spawned}"
    );
}

#[test]
fn two_bash_calls_take_two_spawn_ids() {
    let ctx = spawning_ctx();
    let lines = capture(|| {
        bash("echo one", &ctx);
        bash("echo two", &ctx);
    });

    assert_eq!(
        lines.len(),
        4,
        "two spawns and two outcomes, got: {lines:?}"
    );

    let ids: std::collections::HashSet<&str> = lines
        .iter()
        .map(|line| {
            let after = line
                .split_once("spawn=")
                .unwrap_or_else(|| panic!("no spawn id was recorded: {line}"))
                .1;
            after.split_whitespace().next().expect("a non-empty id")
        })
        .collect();

    assert_eq!(
        ids.len(),
        2,
        "two calls through one context share an id, so their outcomes cannot be told \
         apart: {ids:?}"
    );
}
