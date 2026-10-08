//! Public contract of audit emission.
//!
//! The trail answers "what did the agent do to my machine", so it is a product
//! feature rather than debug output: events must be emitted at a level that is on
//! by default and carry enough to reconstruct a decision.

use std::sync::{Arc, Mutex};

use sandbx_core::{
    AUDIT_TARGET, Access, AuditEvent, FsGuard, SandboxError, SandboxPolicy, SandboxedCommand,
};
use tracing::subscriber::with_default;
use tracing_subscriber::layer::SubscriberExt;

/// `path`, pinned to the object it names — the shape every grant takes (#212).
fn vetted(path: impl AsRef<std::path::Path>) -> sandbx_core::VettedPath {
    sandbx_core::VettedPath::vet(path).expect("an existing path to pin the grant to")
}

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

/// A `wait(2)` status with no process to spawn: the exit code sits in the byte above
/// the signal bits.
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

/// `denied` would name a refusal nothing made, and a model guessing filenames inside a
/// grant leaves nothing else on the trail.
#[test]
fn an_in_grant_miss_records_an_absence() {
    let root = tempfile::tempdir().unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));
    let missing = root.path().join("absent.txt");

    let lines = capture(|| {
        let _ = guard.check_read(&missing);
    });

    assert_eq!(lines.len(), 1, "got: {lines:?}");
    let line = &lines[0];
    assert!(line.contains("decision=absent"), "got: {line}");
    assert!(line.contains("tool=read"), "got: {line}");
    assert!(line.contains(&missing.display().to_string()), "got: {line}");
    assert!(!line.contains("reason"), "absence explains nothing: {line}");
}

/// Outside every root, that a path does not exist is exactly the fact withheld.
#[test]
fn a_miss_outside_every_root_is_not_an_absence() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));

    // Not named "absent": the subject is the path, and a substring assertion on the
    // decision must not be satisfiable by the filename.
    let lines = capture(|| {
        let _ = guard.check_read(&elsewhere.path().join("nope.txt"));
    });

    assert_eq!(lines.len(), 1, "got: {lines:?}");
    assert!(lines[0].contains("decision=denied"), "got: {}", lines[0]);
    assert!(!lines[0].contains("decision=absent"), "got: {}", lines[0]);
}

/// In-grant by its spelling, out of grant by where it points: `absent` here would read as
/// "this host path does not exist" for whatever target the agent chose.
#[cfg(unix)]
#[test]
fn an_absence_behind_a_symlink_is_not_an_absence() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let probe = root.path().join("probe");
    std::os::unix::fs::symlink(elsewhere.path().join("gone.txt"), &probe).unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));

    let lines = capture(|| {
        let _ = guard.check_read(&probe);
    });

    assert_eq!(lines.len(), 1, "got: {lines:?}");
    assert!(lines[0].contains("decision=denied"), "got: {}", lines[0]);
    assert!(!lines[0].contains("decision=absent"), "got: {}", lines[0]);
}

/// `decision=` records the access, and a check is not one (#182).
#[test]
fn a_check_that_opens_nothing_records_nothing() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("present.txt");
    std::fs::write(&file, b"x").unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));

    let lines = capture(|| {
        guard.check_read(&file).unwrap();
    });

    assert!(lines.is_empty(), "got: {lines:?}");
}

#[test]
fn an_opened_file_records_the_access() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("present.txt");
    std::fs::write(&file, b"x").unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));

    let lines = capture(|| {
        guard.open_read(&file).unwrap();
    });

    assert_eq!(lines.len(), 1, "got: {lines:?}");
    assert!(lines[0].contains("decision=allowed"), "got: {}", lines[0]);
    assert!(lines[0].contains("tool=read"), "got: {}", lines[0]);
}

/// EISDIR stands in for the class, a check-to-open swap not being raceable here. The
/// reason must not say the path would not resolve: it had, and the policy had allowed it.
#[test]
fn an_access_that_fails_after_the_check_is_a_refusal() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("not-a-file");
    std::fs::create_dir(&dir).unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(vetted(root.path())));

    let lines = capture(|| {
        let _ = guard.open_write(&dir);
    });

    assert_eq!(lines.len(), 1, "got: {lines:?}");
    assert!(lines[0].contains("decision=denied"), "got: {}", lines[0]);
    assert!(
        lines[0].contains("access did not complete"),
        "got: {}",
        lines[0]
    );
}

/// A record per entry would name thousands of files the walk only listed.
#[test]
fn a_walk_records_one_access() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("a.txt"), b"x").unwrap();
    std::fs::create_dir(root.path().join("sub")).unwrap();
    std::fs::write(root.path().join("sub").join("b.txt"), b"x").unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));

    let lines = capture(|| {
        guard.walk_readable(root.path(), 100).unwrap();
    });

    assert_eq!(lines.len(), 1, "got: {lines:?}");
    assert!(lines[0].contains("decision=allowed"), "got: {}", lines[0]);
    assert!(
        lines[0].contains(&root.path().display().to_string()),
        "got: {}",
        lines[0]
    );
}

#[test]
fn a_listed_directory_records_the_access() {
    let root = tempfile::tempdir().unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));

    let lines = capture(|| {
        guard.read_dir(root.path()).unwrap().unwrap();
    });

    assert_eq!(lines.len(), 1, "got: {lines:?}");
    assert!(lines[0].contains("decision=allowed"), "got: {}", lines[0]);
}

/// ENOTDIR here is the leaf being a regular file, which `check_read` just resolved, so
/// `absent` would name a path demonstrably there. Still an attempt, so still recorded.
#[test]
fn listing_a_regular_file_is_not_an_absence() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("not-a-dir.txt");
    std::fs::write(&file, b"x").unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));

    let lines = capture(|| {
        let _ = guard.read_dir(&file);
    });

    assert_eq!(lines.len(), 1, "got: {lines:?}");
    assert!(lines[0].contains("decision=denied"), "got: {}", lines[0]);
}

/// Silence would be an access attempt with no record, and `absent` a lie — it is there.
#[test]
fn a_listing_the_host_refuses_records_a_refusal() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let locked = root.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

    let lines = capture(|| {
        let _ = guard.read_dir(&locked);
    });

    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();

    assert_eq!(lines.len(), 1, "got: {lines:?}");
    assert!(lines[0].contains("decision=denied"), "got: {}", lines[0]);
    assert!(
        lines[0].contains("access did not complete"),
        "got: {}",
        lines[0]
    );
}

#[test]
fn an_absent_write_parent_records_an_absence() {
    let root = tempfile::tempdir().unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(vetted(root.path())));

    let lines = capture(|| {
        let _ = guard.check_write(&root.path().join("nodir").join("out.txt"));
    });

    assert_eq!(lines.len(), 1, "got: {lines:?}");
    assert!(lines[0].contains("decision=absent"), "got: {}", lines[0]);
    assert!(lines[0].contains("tool=write"), "got: {}", lines[0]);
}

/// `Denied` carries a reason because "denied" alone is not actionable; `Absent` has
/// none to carry, and `tracing` would otherwise vary the event's field set.
#[test]
fn records_an_absence_without_a_reason() {
    let lines = capture(|| {
        AuditEvent::absent("read", "/srv/nope").emit();
    });

    let line = &lines[0];
    assert!(line.contains("decision=absent"), "got: {line}");
    assert!(line.contains("subject=/srv/nope"), "got: {line}");
    assert!(!line.contains("reason"), "got: {line}");
}

/// The one `check_write` refusal that emitted nothing, where every sibling did (#183).
#[test]
fn a_path_naming_no_file_records_its_refusal() {
    let root = tempfile::tempdir().unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(vetted(root.path())));

    // The tail needs an absent parent: a bare `..` canonicalizes and never reaches
    // the branch, so the obvious fixture passes whether the fix is there or not.
    let lines = capture(|| {
        let _ = guard.check_write(&root.path().join("nodir").join(".."));
    });

    assert_eq!(lines.len(), 1, "got: {lines:?}");
    assert!(lines[0].contains("decision=denied"), "got: {}", lines[0]);
    assert!(
        lines[0].contains("path names no file to write"),
        "got: {}",
        lines[0]
    );
}

/// A moved root and a path outside every root are one `decision=denied` apart, so the reason
/// is all an operator counting substitutions has — and the trail and the caller have to agree
/// about which of the two happened (#212).
#[test]
fn a_moved_root_records_the_reason_it_returns() {
    let work = tempfile::tempdir().unwrap();
    let granted = work.path().join("granted");
    let other = work.path().join("other");
    std::fs::create_dir(&granted).unwrap();
    std::fs::create_dir(&other).unwrap();
    std::fs::write(granted.join("notes.txt"), b"hello").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(&granted)));
    std::fs::remove_dir_all(&granted).unwrap();
    std::fs::rename(&other, &granted).unwrap();

    let mut error = None;
    let lines = capture(|| error = guard.check_read(&granted.join("notes.txt")).err());
    let error = error.expect("a refused read of a substituted root");

    assert_eq!(lines.len(), 1, "got: {lines:?}");
    let line = &lines[0];
    assert!(line.contains("decision=denied"), "got: {line}");
    assert!(line.contains("tool=read"), "got: {line}");
    assert_eq!(
        error.label(),
        "root_replaced",
        "the caller was told {error}"
    );
    assert!(
        !line.contains(Access::Read.outside()),
        "the trail read as out of bounds while the caller was told the root moved: {line}"
    );
}

/// The walk is the one refusal with no caller to tell, so the trail is the whole report: a
/// link into a moved root recorded as out of bounds hides the substitution behind the
/// commonest reason there is (#212).
#[test]
fn a_link_into_a_moved_root_records_the_swap() {
    let work = tempfile::tempdir().unwrap();
    let walked = work.path().join("walked");
    let linked = work.path().join("linked");
    let other = work.path().join("other");
    std::fs::create_dir(&walked).unwrap();
    std::fs::create_dir(&linked).unwrap();
    std::fs::create_dir(&other).unwrap();
    std::fs::write(linked.join("target.txt"), b"hello").unwrap();
    // The substitute holds the name too, or the link dangles after the swap and the walk
    // drops it for being unresolvable — a refusal for the wrong reason to be asserting on.
    std::fs::write(other.join("target.txt"), b"planted").unwrap();
    std::os::unix::fs::symlink(linked.join("target.txt"), walked.join("link")).unwrap();

    let guard = FsGuard::new(
        &SandboxPolicy::default()
            .allow_read(vetted(&walked))
            .allow_read(vetted(&linked)),
    );
    // The root the link leads into, not the one being walked: the walk's own root still
    // confirms, so the entry is refused for where it resolves to.
    std::fs::remove_dir_all(&linked).unwrap();
    std::fs::rename(&other, &linked).unwrap();

    let mut walk = None;
    let lines = capture(|| walk = guard.walk_readable(&walked, 16).ok());
    let walk = walk.expect("the walked root itself still confirms");

    assert!(walk.files.is_empty(), "got: {:?}", walk.files);
    let refused = lines
        .iter()
        .find(|line| line.contains("decision=denied"))
        .unwrap_or_else(|| panic!("no refusal was recorded: {lines:?}"));
    assert!(
        !refused.contains(Access::Read.outside()),
        "the link's root was substituted and the trail calls it out of bounds: {refused}"
    );
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
        .allow_read(vetted("/usr"))
        .allow_write(vetted("/tmp"))
        .allow_read_execute(vetted("/bin"))
        .allow_unix_sockets()
        .allow_env("PATH")
        .allow_env("HOME");

    let lines = capture(|| {
        AuditEvent::spawned("/bin/cat", &policy, false).emit();
    });

    let line = &lines[0];
    assert!(line.contains("readable=1"), "got: {line}");
    assert!(line.contains("writable=1"), "got: {line}");
    assert!(line.contains("executable=1"), "got: {line}");
    assert!(line.contains("network=denied"), "got: {line}");
    assert!(line.contains("network_ports=0"), "got: {line}");
    assert!(line.contains("unix_sockets=true"), "got: {line}");
    assert!(line.contains("env=2"), "got: {line}");
    assert!(line.contains("dns_over_tcp=false"), "got: {line}");
    assert!(line.contains("dns_names=0"), "got: {line}");
    assert!(line.contains("pinned=false"), "got: {line}");
}

/// The count, not the names: an internal host name is infrastructure the trail has no reason
/// to carry, and it is the length of the allowlist rather than how many of them resolved.
#[test]
fn records_how_many_names_may_resolve_not_which() {
    let policy = SandboxPolicy::default()
        .allow_dns("vault.internal.example")
        .allow_dns("api.example.com");

    let lines = capture(|| {
        AuditEvent::spawned("/bin/cat", &policy, false).emit();
    });

    let line = &lines[0];
    assert!(line.contains("dns_names=2"), "got: {line}");
    assert!(!line.contains("vault.internal.example"), "got: {line}");
}

/// A matching pin leaves no other mark: the run succeeds exactly as an unpinned one does.
#[test]
fn records_whether_the_entry_point_was_pinned() {
    for (pinned, recorded) in [(false, "pinned=false"), (true, "pinned=true")] {
        let lines = capture(|| {
            AuditEvent::spawned("/bin/cat", &SandboxPolicy::default(), pinned).emit();
        });

        let line = &lines[0];
        assert!(line.contains(recorded), "got: {line}");
    }
}

/// The digest is no secret — it is in `/proc/self/cmdline` — but a boolean keeps every
/// record the same width.
#[test]
fn records_that_a_run_was_pinned_and_not_which_digest() {
    let lines = capture(|| {
        AuditEvent::spawned("/bin/cat", &SandboxPolicy::default(), true).emit();
    });

    let line = &lines[0];
    assert!(line.contains("pinned=true"), "got: {line}");
    assert!(
        !line.contains("sha256") && !line.contains("digest"),
        "the record named a digest: {line}"
    );
}

/// Without this field the trail would under-report the environment: `env` does not count
/// an imposed variable.
#[test]
fn records_whether_a_spawn_set_the_resolver_hint() {
    for (policy, recorded) in [
        (SandboxPolicy::default(), "dns_over_tcp=false"),
        (
            SandboxPolicy::default().hint_dns_over_tcp(),
            "dns_over_tcp=true",
        ),
    ] {
        let lines = capture(|| {
            AuditEvent::spawned("/bin/cat", &policy, false).emit();
        });

        let line = &lines[0];
        assert!(line.contains(recorded), "got: {line}");
    }
}

/// `env` is the length of the allowlist, so counting an imposed variable there would
/// report a name the operator never passed.
#[test]
fn the_hint_is_not_counted_as_an_allowlisted_name() {
    let policy = SandboxPolicy::default()
        .allow_env("PATH")
        .hint_dns_over_tcp();

    let lines = capture(|| {
        AuditEvent::spawned("/bin/cat", &policy, false).emit();
    });

    let line = &lines[0];
    assert!(line.contains("env=1"), "got: {line}");
    assert!(!line.contains("RES_OPTIONS"), "got: {line}");
}

/// A trail that collapsed `any` and `ports` into one label could not say whether a spawn
/// was allowlisted.
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
            AuditEvent::spawned("/bin/cat", &policy, false).emit();
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
        AuditEvent::spawned("/bin/cat", &policy, false).emit();
    });

    let line = &lines[0];
    assert!(line.contains("env=1"), "got: {line}");
    assert!(!line.contains("AWS_SECRET_ACCESS_KEY"), "got: {line}");
}

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

/// The label, not the `Display` prose: a trail is filtered by one and not the other.
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

/// Below the default level the trail would record every spawn and no result.
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

/// `program` is the only thing tying a spawn to its outcome — there is no correlation
/// id — so both records must carry it unchanged.
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
