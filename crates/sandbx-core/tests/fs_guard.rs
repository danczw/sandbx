//! Public contract of [`FsGuard`]: nothing outside an allowed root is reachable.
//!
//! Through the public API only — the same surface a consumer has — so a pass is
//! evidence the boundary holds, not that the test reached internals no caller can.
// `mkfifo` is spawned to build a test fixture: a named pipe cannot be created
// through std. Not code executing around the sandbox, which is what the workspace
// ban on `Command::new` exists to stop.
#![allow(clippy::disallowed_methods)]

use sandbx_core::{FsGuard, SandboxPolicy};

#[test]
fn read_inside_allowed_root_is_permitted() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("notes.txt");
    std::fs::write(&file, b"hello").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(root.path()));

    assert!(guard.check_read(&file).is_ok());
}

#[test]
fn read_outside_allowed_root_is_denied() {
    let allowed = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let secret = elsewhere.path().join("secret.txt");
    std::fs::write(&secret, b"secret").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(allowed.path()));

    assert!(guard.check_read(&secret).is_err());
}

/// A guard comparing string prefixes passes this path — it starts with the allowed
/// root — while pointing outside it.
#[test]
fn parent_traversal_cannot_escape_root() {
    let root = tempfile::tempdir().unwrap();
    let inner = root.path().join("work");
    std::fs::create_dir(&inner).unwrap();
    let outside = root.path().join("outside.txt");
    std::fs::write(&outside, b"nope").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(&inner));

    assert!(
        guard.check_read(&inner.join("../outside.txt")).is_err(),
        "`..` escaped the allowed root"
    );
}

/// The link itself lives in an allowed directory, so only resolving it catches
/// this.
#[cfg(unix)]
#[test]
fn symlink_cannot_escape_root() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let secret = elsewhere.path().join("secret.txt");
    std::fs::write(&secret, b"secret").unwrap();

    let link = root.path().join("innocent.txt");
    std::os::unix::fs::symlink(&secret, &link).unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(root.path()));

    assert!(
        guard.check_read(&link).is_err(),
        "symlink escaped the allowed root"
    );
}

/// A write targets a file that does not exist yet, so the check can require only
/// the parent to resolve.
#[test]
fn write_to_new_file_in_allowed_root_is_permitted() {
    let root = tempfile::tempdir().unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(root.path()));

    let new_file = root.path().join("created-later.txt");
    assert!(!new_file.exists());

    assert!(guard.check_write(&new_file).is_ok());
}

#[test]
fn write_to_new_file_outside_allowed_root_is_denied() {
    let root = tempfile::tempdir().unwrap();
    let inner = root.path().join("work");
    std::fs::create_dir(&inner).unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(&inner));

    assert!(
        guard.check_write(&inner.join("../escaped.txt")).is_err(),
        "`..` escaped the allowed root on the write path"
    );
}

#[test]
fn read_grant_does_not_imply_write() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("notes.txt");
    std::fs::write(&file, b"hello").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(root.path()));

    assert!(guard.check_read(&file).is_ok());
    assert!(
        guard.check_write(&file).is_err(),
        "read access must not grant write access"
    );
}

#[test]
fn default_policy_permits_no_path() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("notes.txt");
    std::fs::write(&file, b"hello").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default());

    assert!(guard.check_read(&file).is_err());
    assert!(guard.check_write(&file).is_err());
}

/// `canonicalize` fails identically on a nonexistent path and on a dangling symlink,
/// so a guard that falls back to resolving only the parent approves the link — and
/// the caller's write then follows it out of the root.
#[cfg(unix)]
#[test]
fn write_to_dangling_symlink_is_denied() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();

    // Target does not exist yet, which is what makes canonicalize fail.
    let outside = elsewhere.path().join("authorized_keys");
    let link = root.path().join("notes.txt");
    std::os::unix::fs::symlink(&outside, &link).unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(root.path()));

    assert!(
        guard.check_write(&link).is_err(),
        "approved a dangling symlink pointing outside the allowed root"
    );
    assert!(
        !outside.exists(),
        "the symlink target was created outside the root"
    );
}

/// The case that fallback exists for must keep working.
#[cfg(unix)]
#[test]
fn write_to_new_file_beside_a_symlink_still_works() {
    let root = tempfile::tempdir().unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(root.path()));

    assert!(guard.check_write(&root.path().join("fresh.txt")).is_ok());
}

/// A *file* is what exercises the per-entry check: `DirEntry::file_type` is
/// lstat-based, so `is_dir()` is false for a directory symlink and the walk never
/// descends into one regardless of the check.
#[cfg(unix)]
#[test]
fn walk_does_not_follow_a_symlink_to_a_file_outside_the_root() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let secret = elsewhere.path().join("secret.txt");
    std::fs::write(&secret, b"SECRET").unwrap();

    std::os::unix::fs::symlink(&secret, root.path().join("innocent.txt")).unwrap();
    std::fs::write(root.path().join("ours.txt"), b"ours").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(root.path()));
    let found = guard.walk_readable(root.path(), usize::MAX).unwrap().files;

    assert!(
        !found.iter().any(|p| p == &secret),
        "walk followed a symlink to a file outside the root: {found:?}"
    );
    assert_eq!(found.len(), 1, "expected only the in-root file: {found:?}");
}

/// Without this, the test above would pass on a walk that skips every symlink.
#[cfg(unix)]
#[test]
fn walk_includes_a_symlink_to_a_file_inside_the_root() {
    let root = tempfile::tempdir().unwrap();
    let real = root.path().join("real.txt");
    std::fs::write(&real, b"real").unwrap();
    std::os::unix::fs::symlink(&real, root.path().join("alias.txt")).unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(root.path()));
    let found = guard.walk_readable(root.path(), usize::MAX).unwrap().files;

    assert!(
        found.contains(&real.canonicalize().unwrap()),
        "got {found:?}"
    );
}

/// A FIFO must not be returned: reading one with no writer blocks forever.
#[cfg(unix)]
#[test]
fn walk_skips_non_regular_files() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("ordinary.txt"), b"x").unwrap();

    let fifo = root.path().join("pipe");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo should run");
    assert!(status.success());

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(root.path()));
    let found = guard.walk_readable(root.path(), usize::MAX).unwrap().files;

    assert!(
        !found.iter().any(|p| p == &fifo),
        "FIFO returned: {found:?}"
    );
    assert_eq!(found.len(), 1, "got {found:?}");
}

#[test]
fn walk_descends_real_subdirectories() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("sub")).unwrap();
    std::fs::write(root.path().join("sub/deep.txt"), b"d").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(root.path()));
    let found = guard.walk_readable(root.path(), usize::MAX).unwrap().files;

    assert_eq!(found.len(), 1, "got {found:?}");
    assert!(found[0].ends_with("deep.txt"));
}

#[test]
fn walk_refuses_a_root_outside_the_policy() {
    let allowed = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(allowed.path()));
    assert!(guard.walk_readable(elsewhere.path(), usize::MAX).is_err());
}

/// `canonicalize` fails differently for a missing file (ENOENT), an unreadable
/// parent (EACCES) and a path that resolves but is out of bounds. Passing the
/// difference back turns the guard into a filesystem oracle: a prompt-injected model
/// can map the host by probing paths and reading the reason.
#[test]
fn refusals_outside_the_policy_are_indistinguishable() {
    let allowed = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let exists = elsewhere.path().join("exists.txt");
    std::fs::write(&exists, b"x").unwrap();
    let missing = elsewhere.path().join("missing.txt");

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(allowed.path()));

    let for_existing = guard.check_read(&exists).unwrap_err().to_string();
    let for_missing = guard.check_read(&missing).unwrap_err().to_string();

    assert!(
        !for_missing.contains("No such file"),
        "refusal leaked that the path does not exist: {for_missing}"
    );
    assert_eq!(
        for_existing.replace("exists.txt", "X"),
        for_missing.replace("missing.txt", "X"),
        "existing and missing paths outside the policy gave different refusals"
    );
}

#[test]
fn write_refusals_outside_the_policy_are_indistinguishable() {
    let allowed = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let exists = elsewhere.path().join("exists.txt");
    std::fs::write(&exists, b"x").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(allowed.path()));

    let for_existing = guard.check_write(&exists).unwrap_err().to_string();
    let for_missing = guard
        .check_write(&elsewhere.path().join("missing.txt"))
        .unwrap_err()
        .to_string();

    assert!(!for_missing.contains("No such file"), "{for_missing}");
    assert_eq!(
        for_existing.replace("exists.txt", "X"),
        for_missing.replace("missing.txt", "X")
    );
}

/// The policy already grants this directory, so reporting a file in it absent
/// discloses nothing the caller was not entitled to learn — and a model told only
/// "refused" would retry a path it is allowed to use.
#[test]
fn a_missing_file_inside_an_allowed_root_still_says_so() {
    let root = tempfile::tempdir().unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(root.path()));

    let error = guard
        .check_read(&root.path().join("absent.txt"))
        .unwrap_err()
        .to_string();

    assert!(
        error.contains("No such file") || error.contains("not found"),
        "an in-root miss should report why: {error}"
    );
}

#[test]
fn a_missing_file_in_an_allowed_subdirectory_still_says_so() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("sub")).unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(root.path()));

    let error = guard
        .check_read(&root.path().join("sub/absent.txt"))
        .unwrap_err()
        .to_string();

    assert!(error.contains("No such file"), "got: {error}");
}

#[test]
fn open_read_returns_a_usable_handle_inside_an_allowed_root() {
    use std::io::Read;

    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("notes.txt"), b"hello").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(root.path()));
    let mut file = guard.open_read(&root.path().join("notes.txt")).unwrap();

    let mut got = String::new();
    file.read_to_string(&mut got).unwrap();
    assert_eq!(got, "hello");
}

#[test]
fn open_read_refuses_a_path_outside_every_allowed_root() {
    let allowed = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    std::fs::write(elsewhere.path().join("secret.txt"), b"secret").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(allowed.path()));

    assert!(
        guard
            .open_read(&elsewhere.path().join("secret.txt"))
            .is_err()
    );
}

#[test]
fn open_write_creates_inside_an_allowed_root() {
    use std::io::Write;

    let root = tempfile::tempdir().unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(root.path()));

    let target = root.path().join("created.txt");
    let mut file = guard.open_write(&target).unwrap();
    file.write_all(b"written").unwrap();
    drop(file);

    assert_eq!(std::fs::read_to_string(&target).unwrap(), "written");
}

#[test]
fn open_write_refuses_a_read_only_grant() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("notes.txt"), b"original").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(root.path()));

    assert!(guard.open_write(&root.path().join("notes.txt")).is_err());
    assert_eq!(
        std::fs::read_to_string(root.path().join("notes.txt")).unwrap(),
        "original"
    );
}

/// Matches the `write` tool's replace-the-file semantics: otherwise a shorter write
/// leaves a tail of the old content.
#[test]
fn open_write_truncates_existing_content() {
    use std::io::Write;

    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("existing.txt");
    std::fs::write(&target, b"a much longer original body").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(root.path()));
    let mut file = guard.open_write(&target).unwrap();
    file.write_all(b"short").unwrap();
    drop(file);

    assert_eq!(std::fs::read_to_string(&target).unwrap(), "short");
}

/// A program needs `Execute` on the binary and `ReadFile` on the libraries its
/// loader pulls in, so execute alone would start nothing; the kernel layer matches,
/// as `AccessFs::from_read` bundles `ReadFile`/`ReadDir` with `Execute`. If `FsGuard`
/// disagrees, `bash` and the native `read` tool answer differently for one policy.
#[test]
fn an_execute_grant_permits_reading() {
    let root = tempfile::tempdir().unwrap();
    let program = root.path().join("program");
    std::fs::write(&program, b"#!/bin/sh\nexit 0\n").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read_execute(root.path()));

    assert!(
        guard.check_read(&program).is_ok(),
        "FsGuard denies a read the kernel layer permits: the two layers disagree"
    );
}

/// The kernel grants `from_read` on that axis and nothing more, so being able to run
/// `ls` must not confer the right to replace it.
#[test]
fn an_execute_grant_does_not_permit_writing() {
    let root = tempfile::tempdir().unwrap();
    let program = root.path().join("program");
    std::fs::write(&program, b"#!/bin/sh\nexit 0\n").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read_execute(root.path()));

    assert!(
        guard.check_write(&program).is_err(),
        "an execute grant must not confer write"
    );
}

/// The same claim as the pairs above, stated over [`Axis::ALL`], so an axis added
/// later cannot slip through the way the execute axis once did.
#[test]
fn every_axis_grants_exactly_what_the_table_says() {
    use sandbx_core::Axis;

    for axis in Axis::ALL {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("subject");
        std::fs::write(&file, b"x").unwrap();

        let grants = axis.grants();
        let guard = FsGuard::new(&SandboxPolicy::default().grant(axis, root.path()));

        assert_eq!(
            guard.check_read(&file).is_ok(),
            grants.read,
            "{axis:?} grants read={}, but FsGuard disagrees: the two enforcement \
             layers are back to enforcing different policies",
            grants.read
        );
        assert_eq!(
            guard.check_write(&file).is_ok(),
            grants.write,
            "{axis:?} grants write={}, but FsGuard disagrees",
            grants.write
        );
    }
}

/// `FsGuard::new` returns `Self` rather than a `Result`, which holds only because a
/// root it cannot resolve is dropped: a policy may name a directory not created yet,
/// and `canonicalize` fails identically on that and on a path it may not traverse, so
/// dropping denies rather than permits and leaves no error to report.
#[test]
fn a_root_that_cannot_be_resolved_is_dropped_rather_than_refused() {
    let root = tempfile::tempdir().unwrap();
    let absent = root.path().join("not-created-yet");
    let real = root.path().join("notes.txt");
    std::fs::write(&real, b"hello").unwrap();

    let guard = FsGuard::new(
        &SandboxPolicy::default()
            .allow_read(&absent)
            .allow_write(&absent),
    );

    assert!(guard.check_read(&absent.join("inside.txt")).is_err());
    assert!(guard.check_write(&absent.join("inside.txt")).is_err());
    // And it did not widen into a sibling that does exist.
    assert!(guard.check_read(&real).is_err());
}

/// The walk collects every readable path into memory first, so an unbounded tree is
/// unbounded memory. The cap stops the walk rather than trimming the result, which is
/// the difference between bounding the work and bounding the answer.
#[test]
fn walk_stops_at_the_file_cap() {
    let root = tempfile::tempdir().unwrap();
    for n in 0..20 {
        std::fs::write(root.path().join(format!("f{n}.txt")), b"x").unwrap();
    }

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(root.path()));
    let walk = guard.walk_readable(root.path(), 5).unwrap();

    assert_eq!(walk.files.len(), 5, "cap not applied");
    assert!(walk.truncated, "cap applied without reporting it");
}

/// The flag is what a tool turns into "there may be more".
#[test]
fn walk_under_the_cap_is_not_truncated() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("a.txt"), b"a").unwrap();
    std::fs::write(root.path().join("b.txt"), b"b").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(root.path()));
    let walk = guard.walk_readable(root.path(), 10).unwrap();

    assert_eq!(walk.files.len(), 2);
    assert!(!walk.truncated);
}

/// Inferring truncation from `files.len() == max` would report this tree as partial,
/// which is why the walk carries the flag rather than letting the caller deduce it.
#[test]
fn walk_of_exactly_the_cap_is_not_truncated() {
    let root = tempfile::tempdir().unwrap();
    for n in 0..4 {
        std::fs::write(root.path().join(format!("f{n}.txt")), b"x").unwrap();
    }

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(root.path()));
    let walk = guard.walk_readable(root.path(), 4).unwrap();

    assert_eq!(walk.files.len(), 4);
    assert!(!walk.truncated, "a tree that exactly fits is not partial");
}
