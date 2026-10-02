//! The channel helper-side degradations cross, from the parent's side.
//!
//! Both best-effort hardening steps run in the re-exec'd helper, which installs no
//! `tracing` subscriber — so until #95 a `Degraded` record was emitted into nothing
//! at all. It now crosses as bytes on a pipe in the helper's stdin slot and the
//! parent emits it, which puts two properties on the critical path that a wire
//! round-trip cannot check: the sandboxed command must not be able to reach that
//! pipe, and its own output must stay byte-exact.
//!
//! The *positive* case — a run on a host where hardening actually degrades — is
//! #94's subject and is not reachable here: it needs a kernel or LSM configuration
//! the test cannot impose, which is the whole reason the record was so easy to
//! lose. `degradation.rs`'s unit tests stand in for the wire; these cover the
//! boundary around it.
//!
//! Gated whole-file, the way `enforcement.rs` is: every test here spawns a real
//! helper, so with the feature off there is nothing left but the capture harness
//! and `-D warnings` would reject it as dead code.
#![cfg(all(feature = "sandbox-integration", target_os = "linux"))]

use std::sync::{Arc, Mutex};

use sandbx_core::{AUDIT_TARGET, SandboxPolicy, SandboxedCommand};
use tracing::subscriber::with_default;
use tracing_subscriber::layer::SubscriberExt;

/// Collects audit events so a test can assert on what was recorded.
///
/// The same shape as the harness in `audit.rs`, repeated rather than shared
/// because cargo gives each `tests/*.rs` its own binary and a `tests/support`
/// module would be compiled into both.
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

fn capture<T>(f: impl FnOnce() -> T) -> (T, Vec<String>) {
    let sink = Captured::default();
    let subscriber = tracing_subscriber::registry().with(sink.clone());
    let out = with_default(subscriber, f);
    (out, sink.lines())
}

/// Run `script` under `sh` in a real sandbox, with the trail captured.
fn sandboxed(script: &str, policy: SandboxPolicy) -> (std::process::Output, Vec<String>) {
    let (result, lines) = capture(|| {
        SandboxedCommand::new("/bin/sh", policy)
            .arg("-c")
            .arg(script)
            .helper(env!("CARGO_BIN_EXE_sandbx-helper"))
            .output()
    });

    (
        result.expect("the sandboxed command should have run"),
        lines,
    )
}

/// The security property the design rests on.
///
/// The parent hands the helper a pipe it reads audit records from, and it arrives
/// in the stdin slot because that is the only descriptor std can pass a child
/// without `unsafe`. So the first helper stage replaces its stdin with `null`
/// before spawning anything — without that line the sandboxed command would
/// inherit a writable descriptor onto sandbx's own audit trail and could put
/// whatever it liked on it.
///
/// Writing to fd 0 from inside the sandbox must therefore reach `/dev/null` and
/// not the channel. The assertion is on the trail rather than on the write's exit
/// status: what matters is that nothing the command wrote was recorded, however
/// the kernel answered it.
///
/// `printf` and not `echo`, and the tab written as an escape the shell expands
/// rather than one this file contains: a literal tab in the script is an `IFS`
/// character, so the shell would split the word and `echo` would rejoin it with a
/// space — the forged line would then reach the channel and be rejected for having
/// no separator, and this test would pass against a sandbox that *could* write it.
#[test]
fn the_sandboxed_command_cannot_write_the_audit_channel() {
    let (output, lines) = sandboxed(
        // `|| true` so the command's own exit status does not depend on whether
        // fd 0 accepted the write; this test is about where the bytes went.
        r"printf 'capability_bounding_set\tforged-by-the-command\n' >&0 || true",
        SandboxPolicy::default()
            .allow_system_executables()
            .allow_read("/dev/null")
            .allow_write("/dev/null"),
    );

    assert!(
        !lines
            .iter()
            .any(|line| line.contains("forged-by-the-command")),
        "the command wrote onto sandbx's audit trail: {lines:?}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !lines.iter().any(|line| line.contains("decision=degraded")),
        "a degradation was recorded that no hardening step reported: {lines:?}"
    );
}

/// The channel must not cost the command its own streams.
///
/// This is what the old placement protected and what putting a subscriber in the
/// helper would have given up: sandbx's records interleaved into the output of the
/// command being sandboxed, indistinguishable from bytes the command itself wrote.
/// Byte-exact on both streams, so a record leaking in would fail here rather than
/// only showing up for whoever was parsing the output.
#[test]
fn the_commands_own_output_carries_no_audit_records() {
    let (output, _) = sandboxed(
        "printf 'to stdout'; printf 'to stderr' >&2",
        SandboxPolicy::default().allow_system_executables(),
    );

    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "to stdout",
        "stdout was not byte-exact"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "to stderr",
        "stderr was not byte-exact"
    );
}

/// A run where nothing degraded must record nothing, or the record stops meaning
/// anything.
///
/// The channel is written only when there is something to report
/// (`degradation::encode` of an empty slice is empty, and the helper skips the
/// write), so an empty channel has to decode to no events rather than to one with
/// blank fields.
#[test]
fn a_run_with_nothing_degraded_records_only_the_spawn() {
    let (_, lines) = sandboxed("true", SandboxPolicy::default().allow_system_executables());

    let degraded: Vec<_> = lines
        .iter()
        .filter(|line| line.contains("decision=degraded"))
        .collect();

    assert!(
        degraded.is_empty(),
        "nothing degraded on this host, but a record says otherwise: {degraded:?}"
    );
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.contains("decision=spawned"))
            .count(),
        1,
        "expected exactly one spawn record: {lines:?}"
    );
}
