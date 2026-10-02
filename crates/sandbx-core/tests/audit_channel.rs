//! The channel helper-side degradations cross, from the parent's side.
//!
//! Both best-effort hardening steps run in the re-exec'd helper, which installs no
//! `tracing` subscriber — so until #95 a `Degraded` record was emitted into nothing
//! at all. It now crosses as bytes on a pipe in the helper's stdin slot and the
//! parent emits it, which puts two properties on the critical path that a wire
//! round-trip cannot check: the sandboxed command must not be able to reach that
//! pipe, and its own output must stay byte-exact.
//!
//! Whether a run here degrades at all is the *host's* choice, not the test's, and
//! both answers are correct: a developer machine without AppArmor's
//! `restrict_unprivileged_userns` drops the bounding set cleanly and records
//! nothing, while Ubuntu 24.04+ and GitHub's runners refuse the drop with `EPERM`
//! and legitimately record one `capability_bounding_set` degradation on every run.
//!
//! So nothing below asserts the *absence* of a `degraded` record — that would be an
//! assertion about the kernel the suite happens to run on, and it would fail on CI
//! for the very reason this change exists. What they assert instead is that a record
//! on the trail came from a hardening step rather than from the command, and that
//! each step reports at most once. `degradation.rs`'s unit tests cover the wire
//! format; making a host degrade *on demand* is #94's subject.
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
/// The forged *detail* is the discriminator, and deliberately so. A host that
/// refuses `PR_CAPBSET_DROP` records a real `capability_bounding_set` degradation
/// on this very run, so the mechanism name cannot tell the two apart, and asserting
/// that no `degraded` record appeared at all would fail on exactly the hosts #95 was
/// filed for. A detail string no hardening step would ever produce can only have
/// come from the command.
///
/// `printf` and not `echo`, and the tab written as an escape the shell expands
/// rather than one this file contains: a literal tab in the script is an `IFS`
/// character, so the shell would split the word and `echo` would rejoin it with a
/// space — the forged line would then reach the channel and be rejected for having
/// no separator, and this test would pass against a sandbox that *could* write it.
/// Checked by removing the `Stdio::null()` in `helper::exec_sandboxed`, which makes
/// this fail — which is what makes it evidence rather than decoration.
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

/// Whatever this host records, the trail has to be well-formed: one spawn, and
/// every degradation naming a real mechanism at most once.
///
/// Deliberately not "nothing degraded". How many records a clean run produces is
/// the host's answer — none where `PR_CAPBSET_DROP` succeeds, one where an LSM
/// refuses it — so requiring either number would make this a test of the kernel
/// underneath rather than of the channel. What is invariant is the *shape*, and
/// three ways of breaking it are worth catching: a blank or unnamed mechanism,
/// which is what an empty channel decoding to a record would look like; the same
/// step reported twice, which is what a short write re-sent or a stale buffer
/// would look like; and more than one spawn, since `record_degradations` runs on
/// both the timeout and the ordinary path and must not re-emit.
#[test]
fn every_record_on_the_trail_names_a_real_mechanism_at_most_once() {
    let (_, lines) = sandboxed("true", SandboxPolicy::default().allow_system_executables());

    let degraded: Vec<_> = lines
        .iter()
        .filter(|line| line.contains("decision=degraded"))
        .collect();

    // The two labels `degradation::Degradation` can emit. Spelled out rather than
    // read from the crate because they are a compatibility surface: this is the
    // trail's view of them, and it should break if a rename reaches it.
    let known = ["capability_bounding_set", "userns_identity_map"];

    for record in &degraded {
        assert!(
            known.iter().any(|m| record.contains(m)),
            "a degradation named a mechanism the crate does not define: {record}"
        );
        assert!(
            !record.contains("detail= "),
            "a degradation reached the trail with no detail: {record}"
        );
    }

    for mechanism in known {
        assert!(
            degraded.iter().filter(|r| r.contains(mechanism)).count() <= 1,
            "{mechanism} reported more than once: {degraded:?}"
        );
    }

    assert_eq!(
        lines
            .iter()
            .filter(|line| line.contains("decision=spawned"))
            .count(),
        1,
        "expected exactly one spawn record: {lines:?}"
    );
}
