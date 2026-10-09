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

/// `grep` measured this one and read nothing of it, and a measurement it makes by
/// opening is a measurement the trail sees (#275).
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
