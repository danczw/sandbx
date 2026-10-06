//! What the shipped subscriber records, and what it drops.
//!
//! These drive the real subscriber from `sandbx_cli::logging` over an in-memory sink, so
//! the filter — which decides what a user sees and what stays internal — is pinned
//! without spawning the binary or capturing a file descriptor.

use std::sync::{Arc, Mutex};

use sandbx_core::{AUDIT_TARGET, AuditEvent, SandboxPolicy};
use tracing_subscriber::util::SubscriberInitExt;

/// An in-memory stand-in for stderr.
///
/// Cloneable over a shared buffer because the applicable `MakeWriter` impl is the one
/// for `Fn() -> impl io::Write`, and the test still has to read back what the writers
/// that factory produced wrote. A bare `Arc<Mutex<Vec<u8>>>` cannot stand in: that impl
/// needs `&Mutex<Vec<u8>>: io::Write`, which it is not.
#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Sink {
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
/// `set_default` rather than `try_init`: it is scoped to this thread, and cargo runs
/// these tests on several threads of one process, where a global subscriber can only be
/// installed once.
fn captured(f: impl FnOnce()) -> String {
    let sink = Sink::default();
    let writer = sink.clone();
    let _guard = sandbx_cli::logging::subscriber(move || writer.clone()).set_default();
    f();
    sink.contents()
}

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

#[test]
fn a_spawn_records_the_policy_shape() {
    let policy = SandboxPolicy::default()
        .allow_read("/srv")
        .allow_write("/tmp/out")
        .allow_unix_sockets()
        .allow_standard_env();

    let output = captured(|| AuditEvent::spawned("/bin/true", &policy).emit());

    assert!(output.contains(r#"decision="spawned""#), "{output}");
    assert!(output.contains(r#"program="/bin/true""#), "{output}");
    assert!(output.contains("readable=1"), "{output}");
    assert!(output.contains("writable=1"), "{output}");
    assert!(output.contains(r#"network="denied""#), "{output}");
    assert!(output.contains("network_ports=0"), "{output}");
    assert!(output.contains("unix_sockets=true"), "{output}");
    assert!(output.contains("env=7"), "{output}");
}

/// The two network fields travel together, so a record cannot say `ports` and name none.
#[test]
fn a_spawn_records_the_shape_of_a_port_allowlist() {
    let policy = SandboxPolicy::default()
        .allow_network_port(443)
        .allow_network_port(80);

    let output = captured(|| AuditEvent::spawned("/bin/true", &policy).emit());

    assert!(output.contains(r#"network="ports""#), "{output}");
    assert!(output.contains("network_ports=2"), "{output}");
}

/// `any` and `ports` are distinguishable on the trail: without the label, a reader could
/// not tell an unrestricted grant from an allowlisted one.
#[test]
fn a_spawn_records_an_unrestricted_network_grant() {
    let policy = SandboxPolicy::default().allow_network();

    let output = captured(|| AuditEvent::spawned("/bin/true", &policy).emit());

    assert!(output.contains(r#"network="any""#), "{output}");
    assert!(output.contains("network_ports=0"), "{output}");
}

/// The one variable the child holds that the `env` count cannot show.
#[test]
fn a_spawn_records_the_resolver_hint() {
    let policy = SandboxPolicy::default().hint_dns_over_tcp();

    let output = captured(|| AuditEvent::spawned("/bin/true", &policy).emit());

    assert!(output.contains("dns_over_tcp=true"), "{output}");
    assert!(
        !output.contains("RES_OPTIONS"),
        "the trail named the variable: {output}"
    );
}

/// `Degraded` is emitted at `INFO` so this filter admits it. Its emitters run in the
/// re-exec'd helper, where no subscriber is installed, so passing the filter is
/// necessary but not sufficient.
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

/// The record closing a run goes through the same filter as the one opening it, so a trail
/// cannot show every spawn and no result.
#[test]
fn an_exit_records_the_code_it_ended_with() {
    use std::os::unix::process::ExitStatusExt;

    let clean = std::process::ExitStatus::from_raw(0);
    let output = captured(|| AuditEvent::exited("/bin/true", &clean).emit());

    assert!(output.contains(r#"decision="exited""#), "{output}");
    assert!(output.contains(r#"program="/bin/true""#), "{output}");
    assert!(output.contains("code=0"), "{output}");
}

/// The reason is rendered as a quoted label rather than prose, which is what a trail can
/// be filtered by.
#[test]
fn a_failed_run_records_a_filterable_reason() {
    let output = captured(|| AuditEvent::failed("/bin/sh", "timeout").emit());

    assert!(output.contains(r#"decision="failed""#), "{output}");
    assert!(output.contains(r#"reason="timeout""#), "{output}");
}

/// The target half of the filter: `INFO` on another target is what a bare
/// `LevelFilter::INFO` would let through.
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

/// The level half of the filter: below `INFO` on the audit target is a diagnostic that
/// borrowed the target, not a decision.
#[test]
fn audit_events_below_info_are_dropped() {
    let output = captured(|| tracing::debug!(target: AUDIT_TARGET, "a best-effort note"));

    assert!(
        output.is_empty(),
        "a sub-INFO event on the audit target was recorded: {output}"
    );
}

/// Asserted rather than inferred from the feature list: the fmt layer's ANSI default
/// keys off the `ansi` feature, which feature unification turns on under
/// `cargo test --workspace` and not under `cargo build`.
#[test]
fn the_output_carries_no_ansi_escapes() {
    let output = captured(|| {
        AuditEvent::denied("write", "/etc/shadow", "outside every writable root").emit()
    });

    assert!(!output.is_empty(), "nothing was recorded");
    assert!(!output.contains('\u{1b}'), "{output:?}");
}
