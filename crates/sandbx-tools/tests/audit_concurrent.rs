//! Two spawns overlapping in time, which is what #242 will make ordinary.
//!
//! Today the turn loop awaits each `spawn_blocking` before the next, so two sandboxed
//! children never overlap in one process and pairing a spawn to its outcome works
//! *positionally*. That invariant lives in `sandbx-turn` and the records relying on it live
//! in `sandbx-core`, which cannot see it — so this drives two concurrent calls through one
//! `ExecutionContext` and asserts the pairing holds without it (#249).
//!
//! Its own binary because the subscriber has to be the global one: the threads that emit
//! are not the thread that asked, and a `set_default` subscriber is thread-local — the test
//! would capture nothing and pass. `context/guide-logging.md` has the rule.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::{fmt, thread};

use sandbx_core::{AUDIT_TARGET, SandboxPolicy};
use sandbx_tools::{BuiltinTool, ExecutionContext};
use serde_json::json;
use tracing_subscriber::layer::SubscriberExt;

/// The session id the context names, as all four records must carry.
const SESSION: &str = "abc123";

/// Collects audit records from whichever thread emitted them.
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
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        self.0.push_str(&format!("{}={value:?} ", field.name()));
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.push_str(&format!("{}={value} ", field.name()));
    }
}

/// The `spawn=` of one record, which this harness writes unquoted.
fn spawn_id(line: &str) -> &str {
    let after = line
        .split_once("spawn=")
        .unwrap_or_else(|| panic!("no spawn id was recorded: {line}"))
        .1;

    after
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("the spawn id is empty: {line}"))
}

#[test]
fn concurrent_calls_keep_their_records_apart() {
    let sink = Captured::default();
    tracing::subscriber::set_global_default(tracing_subscriber::registry().with(sink.clone()))
        .expect("one global subscriber per process, and this binary holds one test");

    // The helper does not exist, so each call is a `spawned` and a `failed` with no kernel
    // and no command ever executed.
    let ctx = ExecutionContext::for_session(SandboxPolicy::default(), SESSION.to_string())
        .with_helper("/nonexistent/helper");

    let threads: Vec<_> = ["echo one", "echo two"]
        .into_iter()
        .map(|command| {
            // Cloned per thread, as `sandbx-turn` clones it per call to cross
            // `spawn_blocking`'s `'static` boundary.
            let ctx = ctx.clone();
            thread::spawn(move || {
                let _ = BuiltinTool::Bash.execute(json!({ "command": command }), &ctx);
            })
        })
        .collect();

    for thread in threads {
        thread.join().expect("a calling thread should not panic");
    }

    let lines = sink.0.lock().unwrap().clone();
    assert_eq!(
        lines.len(),
        4,
        "two spawns and two outcomes, got: {lines:?}"
    );

    let ids: Vec<&str> = lines.iter().map(|line| spawn_id(line)).collect();
    let distinct: HashSet<&str> = ids.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        2,
        "two overlapping runs share one id, so neither outcome can be attributed: {ids:?}"
    );

    for id in &distinct {
        let records: Vec<&String> = lines.iter().filter(|line| spawn_id(line) == *id).collect();

        assert_eq!(
            records.len(),
            2,
            "{id} names {} records, where a run is exactly two: {records:?}",
            records.len()
        );
        assert!(
            records.iter().any(|line| line.contains("decision=spawned"))
                && records.iter().any(|line| line.contains("decision=failed")),
            "{id} does not name one spawn and one outcome: {records:?}"
        );
    }

    // The evidence both threads ran: a count of four passes if one thread ran twice, and
    // the commands are what tell the two runs apart in the first place.
    for command in ["echo one", "echo two"] {
        assert!(
            lines
                .iter()
                .any(|line| line.contains(&format!(r#"args=["-c", "{command}"]"#))),
            "{command:?} reached no record, so one thread ran twice: {lines:?}"
        );
    }
}
