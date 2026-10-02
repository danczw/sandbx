//! What the shipped subscriber records, and what it drops.
//!
//! The audit trail only exists if something is listening: before #89 every
//! `AuditEvent::emit()` in the workspace reached a process with no subscriber
//! installed, so `sandbx sandbox-run` recorded nothing at all. These drive the
//! real subscriber from `sandbx_cli::logging` over an in-memory sink, so the
//! filter — which decides what a user sees and what stays internal — is pinned
//! without spawning the binary or capturing a file descriptor.

use std::sync::{Arc, Mutex};

use sandbx_core::{AUDIT_TARGET, AuditEvent, SandboxPolicy};
use tracing_subscriber::util::SubscriberInitExt;

/// An in-memory stand-in for stderr.
///
/// Cloneable, and writes through a shared buffer, because the `MakeWriter` impl
/// that applies here is the one for `Fn() -> impl io::Write`: the subscriber
/// takes a *factory*, and the test still has to read back what the writers it
/// produced wrote. `Arc<Mutex<Vec<u8>>>` cannot stand in — that `MakeWriter`
/// impl needs `&Mutex<Vec<u8>>: io::Write`, which it is not.
#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Sink {
    /// Everything written so far, as text.
    fn contents(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl std::io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Run `f` under the shipped subscriber and return everything it wrote.
///
/// `set_default` rather than `try_init`: it is scoped to this thread, and cargo
/// runs the tests in this file on several threads of one process, where a global
/// subscriber can only be installed once.
fn captured(f: impl FnOnce()) -> String {
    let sink = Sink::default();
    let writer = sink.clone();
    let _guard = sandbx_cli::logging::subscriber(move || writer.clone()).set_default();
    f();
    sink.contents()
}

/// The regression #89 names: an audit event has to reach the output at all.
///
/// Before the subscriber existed this produced zero bytes no matter how `RUST_LOG`
/// was set, which is what made the "product feature rather than debug output"
/// framing in `audit.rs` false end to end.
#[test]
fn an_audit_event_reaches_the_output() {
    let output = captured(|| AuditEvent::allowed("read", "/srv").emit());

    assert!(!output.is_empty(), "the audit trail reached no writer");
    assert!(output.contains("sandbx::audit"), "{output}");
    assert!(output.contains("INFO"), "{output}");
    assert!(output.contains(r#"decision="allowed""#), "{output}");
    assert!(output.contains(r#"tool="read""#), "{output}");
    assert!(output.contains(r#"subject="/srv""#), "{output}");
}

/// The one event `sandbox-run` emits today, so if any single event has to
/// survive the real filter it is this one.
///
/// The six `FsGuard` sites are unreachable from the CLI until a tool-running
/// subcommand lands; a spawn is the whole of what a user sees recorded now.
#[test]
fn a_spawn_records_the_policy_shape() {
    let policy = SandboxPolicy::default()
        .allow_read("/srv")
        .allow_write("/tmp/out")
        .allow_unix_sockets();

    let output = captured(|| AuditEvent::spawned("/bin/true", &policy).emit());

    assert!(output.contains(r#"decision="spawned""#), "{output}");
    assert!(output.contains(r#"program="/bin/true""#), "{output}");
    assert!(output.contains("readable=1"), "{output}");
    assert!(output.contains("writable=1"), "{output}");
    assert!(output.contains("network=false"), "{output}");
    assert!(output.contains("unix_sockets=true"), "{output}");
}

/// A weakened sandbox has to clear the filter, since that is the record nobody
/// can afford to miss.
///
/// `Degraded` was moved off a raw `debug!` and onto `AuditEvent` at `INFO`
/// precisely so it survives the default verbosity. This pins the subscriber half
/// of that: the filter admits it. Note that the only two emitters today sit in
/// `helper/hardening.rs`, which runs in the re-exec'd helper where no subscriber
/// is installed — so passing the filter is necessary but not yet sufficient.
#[test]
fn a_degraded_hardening_step_reaches_the_output() {
    let output = captured(|| {
        AuditEvent::degraded("capability_bounding_set", "left as inherited: EPERM").emit()
    });

    assert!(output.contains(r#"decision="degraded""#), "{output}");
    assert!(
        output.contains(r#"mechanism="capability_bounding_set""#),
        "{output}"
    );
    assert!(output.contains("left as inherited"), "{output}");
}

/// Making the audit trail visible must not make the internals visible with it.
///
/// The `INFO`-on-another-target case is the one a bare `LevelFilter::INFO` would
/// let through, so this pins the *target* half of the filter rather than the
/// level half below it.
#[test]
fn diagnostics_from_other_targets_are_dropped() {
    let output = captured(|| {
        tracing::debug!("an internal note");
        tracing::info!(target: "sandbx_core::command", "a loud internal note");
    });

    assert!(
        output.is_empty(),
        "non-audit diagnostics reached the user: {output}"
    );
}

/// A record is a record of decisions, not of everything on the target.
///
/// Anything emitted on the audit target below `INFO` is a diagnostic that has
/// borrowed the target, not a decision, and the filter is what keeps the
/// distinction. `AuditEvent::emit` only ever emits at `INFO`, so this pins the
/// boundary rather than any current caller.
#[test]
fn audit_events_below_info_are_dropped() {
    let output = captured(|| tracing::debug!(target: AUDIT_TARGET, "a best-effort note"));

    assert!(
        output.is_empty(),
        "a sub-INFO event on the audit target was recorded: {output}"
    );
}

/// The record gets piped to files and grepped, and escape codes in a file are
/// damage.
///
/// Asserted rather than inferred from the feature list: the fmt layer's ANSI
/// default keys off the `ansi` feature, which `cargo test --workspace` turns on
/// through feature unification even though `cargo build` does not.
#[test]
fn the_output_carries_no_ansi_escapes() {
    let output = captured(|| {
        AuditEvent::denied("write", "/etc/shadow", "outside every allowed root").emit()
    });

    assert!(!output.is_empty(), "nothing was recorded");
    assert!(!output.contains('\u{1b}'), "{output:?}");
}
