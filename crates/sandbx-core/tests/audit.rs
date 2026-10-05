//! Public contract of audit emission.
//!
//! The trail answers "what did the agent do to my machine", so it is a product
//! feature rather than debug output: events must be emitted at a level that is on
//! by default and carry enough to reconstruct a decision.

use std::sync::{Arc, Mutex};

use sandbx_core::{AUDIT_TARGET, AuditEvent, SandboxError, SandboxPolicy, SandboxedCommand};
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

/// A `wait(2)` status as the kernel encodes one, with no process to spawn: an exit code
/// sits in the byte above the signal bits, which is what `from_raw` takes.
fn status(raw: i32) -> std::process::ExitStatus {
    use std::os::unix::process::ExitStatusExt;

    std::process::ExitStatus::from_raw(raw)
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
        AuditEvent::denied("read", "/etc/shadow", "outside every readable root").emit();
    });

    let line = &lines[0];
    assert!(line.contains("decision=denied"), "got: {line}");
    assert!(line.contains("outside every readable root"), "got: {line}");
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
    assert!(line.contains("network=denied"), "got: {line}");
    assert!(line.contains("network_ports=0"), "got: {line}");
    assert!(line.contains("unix_sockets=true"), "got: {line}");
    assert!(line.contains("env=2"), "got: {line}");
}

/// Three shapes of network grant, three labels. A trail that collapsed `any` and `ports`
/// into one could not say whether a spawn was allowlisted.
#[test]
fn records_which_shape_of_network_grant_a_spawn_had() {
    for (policy, network, count) in [
        (SandboxPolicy::default(), "denied", 0),
        (SandboxPolicy::default().allow_network(), "any", 0),
        (
            SandboxPolicy::default()
                .allow_network_port(443)
                .allow_network_port(80),
            "ports",
            2,
        ),
    ] {
        let lines = capture(|| {
            AuditEvent::spawned("/bin/cat", &policy).emit();
        });

        let line = &lines[0];
        assert!(line.contains(&format!("network={network} ")), "got: {line}");
        assert!(
            line.contains(&format!("network_ports={count} ")),
            "got: {line}"
        );
    }
}

/// A name on the trail is one edit away from the value beside it; the count is
/// enough.
#[test]
fn records_how_many_variables_passed_not_which() {
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

/// A trail that cannot tell a clean exit from a failing one cannot answer what the run
/// did, which is the question it exists for.
#[test]
fn records_the_code_a_command_exited_with() {
    for code in [0, 42] {
        let lines = capture(|| {
            AuditEvent::exited("/bin/true", &status(code << 8)).emit();
        });

        assert_eq!(lines.len(), 1, "expected exactly one audit event");
        let line = &lines[0];
        assert!(line.contains("decision=exited"), "got: {line}");
        assert!(line.contains(&format!("code={code} ")), "got: {line}");
    }
}

/// The number on the trail is the number `sandbx` exits with, so a command seccomp shot
/// reads as a death rather than as a success.
#[test]
fn records_a_signal_death_the_way_a_shell_does() {
    let lines = capture(|| {
        AuditEvent::exited("/bin/sh", &status(libc::SIGKILL)).emit();
    });

    let line = &lines[0];
    assert!(line.contains("decision=exited"), "got: {line}");
    assert!(
        line.contains(&format!("code={} ", 128 + libc::SIGKILL)),
        "got: {line}"
    );
}

/// A killed run has no status of its own, and `exited code=137` would claim the command
/// chose that fate.
#[test]
fn records_a_timeout_as_a_failed_run() {
    let killed = SandboxError::TimedOut {
        after: std::time::Duration::from_secs(1),
    };

    let lines = capture(|| {
        AuditEvent::failed("/bin/sh", killed.label()).emit();
    });

    let line = &lines[0];
    assert!(line.contains("decision=failed"), "got: {line}");
    assert!(line.contains("reason=timeout"), "got: {line}");
}

/// Every refusal names itself, so a trail can be filtered by what stopped the run rather
/// than by prose that may be reworded.
#[test]
fn records_a_failure_to_start_under_its_own_reason() {
    let refused = SandboxError::SpawnFailed {
        detail: "could not start the sandbox helper",
        source: std::io::Error::from(std::io::ErrorKind::NotFound),
    };

    let lines = capture(|| {
        AuditEvent::failed("/bin/sh", refused.label()).emit();
    });

    let line = &lines[0];
    assert!(line.contains("reason=spawn_failed"), "got: {line}");
    assert!(!line.contains("timeout"), "got: {line}");
}

/// The issue's own case: a helper that started and a command that never existed are
/// different facts, and collapsing them hides the second one entirely.
#[test]
fn an_exec_failure_and_a_spawn_failure_differ() {
    let missing = SandboxError::ExecFailed {
        source: std::io::Error::from(std::io::ErrorKind::NotFound),
    };

    assert_ne!(
        missing.label(),
        SandboxError::SpawnFailed {
            detail: "could not start the sandbox helper",
            source: std::io::Error::from(std::io::ErrorKind::NotFound),
        }
        .label(),
        "a command that was never executed reads as a helper that never started"
    );

    let lines = capture(|| {
        AuditEvent::failed("/nonexistent", missing.label()).emit();
    });

    assert!(lines[0].contains("reason=exec_failed"), "got: {}", lines[0]);
}

/// An outcome below the default level leaves a trail that records every spawn and no
/// result.
#[test]
fn an_outcome_is_emitted_at_info_not_debug() {
    let sink = Captured::default();
    let subscriber = tracing_subscriber::registry()
        .with(sink.clone())
        .with(tracing::level_filters::LevelFilter::INFO);
    with_default(subscriber, || {
        AuditEvent::exited("/bin/true", &status(0)).emit();
    });

    assert_eq!(
        sink.lines().len(),
        1,
        "the outcome was filtered out at INFO; how a run ended must not be debug-level"
    );
}

/// `program` is the only thing tying a spawn to its outcome — there is no correlation id
/// until sandbx has a session concept (#108) — so both records must carry it unchanged.
#[test]
fn a_spawn_and_its_outcome_name_one_program() {
    let lines = capture(|| {
        let _ = SandboxedCommand::new("/bin/true", SandboxPolicy::default())
            .helper("/nonexistent/helper")
            .output();
    });

    for line in &lines {
        assert!(line.contains("program=/bin/true"), "got: {line}");
    }
    assert_eq!(lines.len(), 2, "a spawn and its outcome, got: {lines:?}");
}

/// A spawn that never got as far as a command still ends the trail: the record the
/// operator greps for is the one saying the run is over.
#[test]
fn a_helper_that_cannot_start_closes_the_trail() {
    let lines = capture(|| {
        let _ = SandboxedCommand::new("/bin/true", SandboxPolicy::default())
            .helper("/nonexistent/helper")
            .output();
    });

    assert_eq!(lines.len(), 2, "got: {lines:?}");
    assert!(lines[0].contains("decision=spawned"), "got: {lines:?}");
    assert!(lines[1].contains("decision=failed"), "got: {lines:?}");
    assert!(lines[1].contains("reason=spawn_failed"), "got: {lines:?}");
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
