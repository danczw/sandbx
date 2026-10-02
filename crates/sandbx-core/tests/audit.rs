//! Public contract of audit emission.
//!
//! The trail answers "what did the agent do to my machine", so it is a product
//! feature rather than debug output: events must be emitted at a level that is on
//! by default and carry enough to reconstruct a decision.

use std::sync::{Arc, Mutex};

use sandbx_core::{AUDIT_TARGET, AuditEvent, SandboxPolicy};
use tracing::subscriber::with_default;
use tracing_subscriber::layer::SubscriberExt;

/// Collects audit events so a test can assert on what was recorded.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<String>>>);

impl Captured {
    fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

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
    sink.lines()
}

#[test]
fn records_an_allowed_execution() {
    let lines = capture(|| {
        AuditEvent::allowed("bash", "/bin/ls").emit();
    });

    assert_eq!(lines.len(), 1, "expected exactly one audit event");
    let line = &lines[0];
    assert!(line.contains("decision=allowed"), "got: {line}");
    assert!(line.contains("tool=bash"), "got: {line}");
    assert!(line.contains("subject=/bin/ls"), "got: {line}");
}

#[test]
fn records_a_refusal_with_its_reason() {
    let lines = capture(|| {
        AuditEvent::denied("read", "/etc/shadow", "outside every allowed root").emit();
    });

    let line = &lines[0];
    assert!(line.contains("decision=denied"), "got: {line}");
    assert!(line.contains("outside every allowed root"), "got: {line}");
}

/// Audit that only appears under `RUST_LOG=debug` is off for everyone who did
/// not opt in.
#[test]
fn is_emitted_at_info_not_debug() {
    let lines = capture(|| {
        AuditEvent::allowed("bash", "/bin/ls").emit();
    });
    assert_eq!(lines.len(), 1);

    let sink = Captured::default();
    let subscriber = tracing_subscriber::registry()
        .with(sink.clone())
        .with(tracing::level_filters::LevelFilter::INFO);
    with_default(subscriber, || {
        AuditEvent::allowed("bash", "/bin/ls").emit();
    });

    assert_eq!(
        sink.lines().len(),
        1,
        "audit event was filtered out at INFO; it must not be a debug-level event"
    );
}

#[test]
fn records_the_policy_shape_of_a_spawn() {
    let policy = SandboxPolicy::default()
        .allow_read("/usr")
        .allow_write("/tmp/work")
        .allow_read_execute("/bin")
        .allow_unix_sockets()
        .allow_env("PATH")
        .allow_env("HOME");

    let lines = capture(|| {
        AuditEvent::spawned("/bin/cat", &policy).emit();
    });

    let line = &lines[0];
    assert!(line.contains("readable=1"), "got: {line}");
    assert!(line.contains("writable=1"), "got: {line}");
    assert!(line.contains("executable=1"), "got: {line}");
    assert!(line.contains("network=false"), "got: {line}");
    assert!(line.contains("unix_sockets=true"), "got: {line}");
    assert!(line.contains("env=2"), "got: {line}");
}

/// A name on the trail is one edit away from the value beside it; the count is
/// enough.
#[test]
fn records_how_many_variables_a_spawn_passed_not_which() {
    let policy = SandboxPolicy::default().allow_env("AWS_SECRET_ACCESS_KEY");

    let lines = capture(|| {
        AuditEvent::spawned("/bin/cat", &policy).emit();
    });

    let line = &lines[0];
    assert!(line.contains("env=1"), "got: {line}");
    assert!(!line.contains("AWS_SECRET_ACCESS_KEY"), "got: {line}");
}

/// A hardening step that did not take effect is part of what the sandbox did, so
/// it belongs on the trail beside the decisions.
#[test]
fn records_a_degraded_hardening_step() {
    let lines = capture(|| {
        AuditEvent::degraded(
            "userns_identity_map",
            "permission denied, running as nobody",
        )
        .emit();
    });

    assert_eq!(lines.len(), 1, "expected exactly one audit event");
    let line = &lines[0];
    assert!(line.contains("decision=degraded"), "got: {line}");
    assert!(
        line.contains("mechanism=userns_identity_map"),
        "got: {line}"
    );
    assert!(line.contains("running as nobody"), "got: {line}");
}

/// A degradation recorded below the default level is a weaker sandbox with no
/// trace of why.
#[test]
fn a_degradation_is_emitted_at_info_not_debug() {
    let sink = Captured::default();
    let subscriber = tracing_subscriber::registry()
        .with(sink.clone())
        .with(tracing::level_filters::LevelFilter::INFO);
    with_default(subscriber, || {
        AuditEvent::degraded("capability_bounding_set", "operation not permitted").emit();
    });

    assert_eq!(
        sink.lines().len(),
        1,
        "degradation was filtered out at INFO; a weakened sandbox must not be a debug-level event"
    );
}
