//! How a real run ends, from the parent's side.
//!
//! The record a run closes with is assembled from two things a wire round-trip cannot
//! produce together: the status the helper relayed, and what crossed the audit channel. A
//! command that was never executed is the case that needs both — the helper exits non-zero
//! on its behalf, so only the channel distinguishes it from a command that exited 1.
//!
//! Gated whole-file: every test spawns a real helper, so with the feature off `-D warnings`
//! would reject the capture harness as dead code.
#![cfg(all(feature = "sandbox-integration", target_os = "linux"))]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use sandbx_core::{AUDIT_TARGET, SandboxError, SandboxPolicy, SandboxedCommand};
use tracing::subscriber::with_default;
use tracing_subscriber::layer::SubscriberExt;

/// Collects audit events so a test can assert on what was recorded.
///
/// Repeated from `audit.rs` rather than shared: cargo gives each `tests/*.rs` its own
/// binary.
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

/// The result *and* the trail: the outcome record is a claim about the run, so a test that
/// could not see both would be asserting against itself.
type Run = (Result<std::process::Output, SandboxError>, Vec<String>);

fn run(command: SandboxedCommand) -> Run {
    let sink = Captured::default();
    let subscriber = tracing_subscriber::registry().with(sink.clone());
    let result = with_default(subscriber, || command.output());

    (result, sink.lines())
}

/// Run `script` under `sh` in a real sandbox, with the trail captured.
fn sandboxed(script: &str) -> Run {
    run(SandboxedCommand::new(
        "/bin/sh",
        SandboxPolicy::default().allow_system_executables(),
    )
    .arg("-c")
    .arg(script)
    .helper(env!("CARGO_BIN_EXE_sandbx-helper")))
}

/// The one record carrying how the run ended, which every test here needs and exactly one
/// of which must exist.
fn outcome(lines: &[String]) -> &str {
    let mut found = lines
        .iter()
        .filter(|line| line.contains("decision=exited") || line.contains("decision=failed"));

    let record = found
        .next()
        .unwrap_or_else(|| panic!("no outcome: {lines:?}"));
    assert!(found.next().is_none(), "two outcomes: {lines:?}");

    record
}

#[test]
fn a_clean_run_records_the_code_it_exited_with() {
    let (result, lines) = sandboxed("true");

    assert!(result.is_ok(), "the probe command did not run: {result:?}");
    let record = outcome(&lines);
    assert!(record.contains("decision=exited"), "got: {record}");
    assert!(record.contains("code=0 "), "got: {record}");
}

/// A trail recording every run as over without saying how it went answers nothing a
/// reviewer asks of it.
#[test]
fn a_nonzero_exit_reaches_the_trail() {
    let (_, lines) = sandboxed("exit 42");

    assert!(outcome(&lines).contains("code=42 "), "got: {lines:?}");
}

#[test]
fn a_timeout_records_a_failure_not_an_exit() {
    let (result, lines) = run(SandboxedCommand::new(
        "/bin/sh",
        SandboxPolicy::default().allow_system_executables(),
    )
    .arg("-c")
    .arg("sleep 30")
    .helper(env!("CARGO_BIN_EXE_sandbx-helper"))
    .timeout(Duration::from_millis(200)));

    assert!(
        matches!(result, Err(SandboxError::TimedOut { .. })),
        "the command outlived its limit and was not killed: {result:?}"
    );

    let record = outcome(&lines);
    assert!(record.contains("decision=failed"), "got: {record}");
    assert!(record.contains("reason=timeout"), "got: {record}");
}

/// The issue's own reproducer. The helper relays its own non-zero exit for a command it
/// could not become, so without the channel this run is indistinguishable from a command
/// that ran and exited 1.
#[test]
fn a_program_that_does_not_exist_never_exits() {
    let (_, lines) = run(SandboxedCommand::new(
        "/nonexistent-binary",
        SandboxPolicy::default().allow_system_executables(),
    )
    .helper(env!("CARGO_BIN_EXE_sandbx-helper")));

    let record = outcome(&lines);
    assert!(record.contains("decision=failed"), "got: {record}");
    assert!(record.contains("reason=exec_failed"), "got: {record}");
}

/// Two outcome records would double-count every run in an aggregate, and `outcome` is
/// what refuses them; this names the property so a second emit fails here by name.
#[test]
fn a_run_records_exactly_one_outcome() {
    let (_, lines) = sandboxed("true");

    outcome(&lines);
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.contains("decision=spawned"))
            .count(),
        1,
        "expected one spawn record to close: {lines:?}"
    );
}

/// So a reader can stop at it. Any `degraded` record is written while the helper is still
/// running, which is before the parent knows how the run ended, on every host.
#[test]
fn the_outcome_is_the_last_record_of_a_run() {
    let (_, lines) = sandboxed("true");

    let last = lines.last().unwrap_or_else(|| panic!("no records at all"));
    assert_eq!(outcome(&lines), last, "got: {lines:?}");
}
