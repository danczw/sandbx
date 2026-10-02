//! The channel helper-side degradations cross, from the parent's side.
//!
//! Both hardening steps run in the re-exec'd helper, which installs no `tracing`
//! subscriber, so a `Degraded` record crosses as bytes on a pipe in the helper's
//! stdin slot and the parent emits it. Hence two properties a wire round-trip
//! cannot check: the sandboxed command must not reach that pipe, and its own
//! output must stay byte-exact. Whether a run degrades is the host's answer, so
//! only the one test holding the host's answer in a predicate asserts a record is
//! present or absent.
//!
//! Gated whole-file: every test spawns a real helper, so with the feature off
//! `-D warnings` would reject the capture harness as dead code.
#![cfg(all(feature = "sandbox-integration", target_os = "linux"))]

use std::sync::{Arc, Mutex};

use sandbx_core::{AUDIT_TARGET, SandboxPolicy, SandboxedCommand};
use tracing::subscriber::with_default;
use tracing_subscriber::layer::SubscriberExt;

/// Collects audit events so a test can assert on what was recorded.
///
/// Repeated from `audit.rs` rather than shared: cargo gives each `tests/*.rs` its
/// own binary.
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

/// Can this machine drop the capability bounding set at all? Repeated from
/// `enforcement.rs`, which documents the LSM behaviour behind it, because cargo
/// gives each `tests/*.rs` its own binary. Keep the two copies identical.
fn bounding_set_is_droppable() -> bool {
    use std::os::unix::fs::MetadataExt;

    // The restriction covers *unprivileged* userns only, so a run as root holds
    // `CAP_SETPCAP` in the new namespace whatever the sysctl says. Off `/proc/self`'s
    // owner because `libc::geteuid` is `unsafe` and this crate forbids that.
    let root = std::fs::metadata("/proc/self")
        .map(|proc_self| proc_self.uid() == 0)
        .unwrap_or(false);

    root || std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
        .map(|value| value.trim() != "1")
        .unwrap_or(true)
}

/// The condition and not merely the call: a host whose LSM strips `CAP_SETPCAP`
/// from a fresh user namespace refuses `PR_CAPBSET_DROP` for real, which is the
/// case `SECURITY.md` promises a `degraded` record for.
///
/// Both branches assert, because returning early on one would report `ok` without
/// checking anything — the argument
/// `the_bounding_set_is_cleared_or_left_inherited` makes about the same
/// two hosts.
#[test]
fn the_bounding_set_degrades_only_on_a_refused_drop() {
    let (output, lines) = sandboxed("true", SandboxPolicy::default().allow_system_executables());

    // Without this the droppable branch passes on a run that never happened: a command
    // the sandbox refused records no degradation either.
    assert!(
        output.status.success(),
        "the probe command did not run, so the trail says nothing about the drop: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let recorded = lines.iter().any(|line| {
        line.contains("decision=degraded") && line.contains("mechanism=capability_bounding_set")
    });

    if bounding_set_is_droppable() {
        assert!(
            !recorded,
            "this kernel permits the drop, so nothing should have reported it as \
             degraded: {lines:?}"
        );
    } else {
        assert!(
            recorded,
            "this kernel refuses PR_CAPBSET_DROP, so the bounding set is left as \
             inherited and the trail must say so: {lines:?}"
        );
    }
}

/// Without the first helper stage replacing its stdin with `null`, the sandboxed
/// command inherits a writable descriptor onto sandbx's own audit trail.
///
/// The forged *detail* is the discriminator, not the mechanism name: a host
/// refusing `PR_CAPBSET_DROP` records a real `capability_bounding_set` degradation
/// on this very run. The tab must stay a `printf` escape — a literal tab is an
/// `IFS` character, so the shell would split the word and the rejoined line would
/// be rejected for having no separator while the sandbox had in fact let it
/// through.
#[test]
fn the_command_cannot_write_the_audit_channel() {
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

/// A record interleaved into the command's own output is indistinguishable from
/// bytes the command wrote, so both streams are compared byte-exact.
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

/// Shape, not count: how many records a clean run produces is the host's answer.
/// A blank mechanism is what an empty channel decoding to a record looks like, a
/// repeated one a re-sent short write, and a second spawn record
/// `record_degradations` re-emitting on both the timeout and the ordinary path.
#[test]
fn every_record_names_a_real_mechanism_once() {
    let (_, lines) = sandboxed("true", SandboxPolicy::default().allow_system_executables());

    let degraded: Vec<_> = lines
        .iter()
        .filter(|line| line.contains("decision=degraded"))
        .collect();

    // Spelled out rather than read from the crate: these labels are a compatibility
    // surface, so a rename should break the trail's view of them.
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
