//! Public contract of [`FsGuard`]: nothing outside an allowed root is reachable.
//!
//! Through the public API only — the same surface a consumer has — so a pass is evidence
//! the boundary holds, not that the test reached internals no caller can.
// `mkfifo` is spawned to build a test fixture: a named pipe cannot be created through std.
// The workspace ban on `Command::new` exists to stop code executing around the sandbox.
#![allow(clippy::disallowed_methods)]

use sandbx_core::{Access, FsGuard, SandboxError, SandboxPolicy, VettedPath};

/// `path`, pinned to the object it names — the shape every grant takes (#212).
fn vetted(path: impl AsRef<std::path::Path>) -> VettedPath {
    VettedPath::vet(path).expect("an existing path to pin the grant to")
}

/// Put `with` at `granted`'s name: one spelling, a different real directory. `rename` over a
/// directory needs the target gone, hence the removal first.
fn substitute(granted: &std::path::Path, with: &std::path::Path) {
    std::fs::remove_dir_all(granted).expect("the granted directory to go");
    std::fs::rename(with, granted).expect("a substitution at the same name");
}

#[test]
fn read_inside_allowed_root_is_permitted() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("notes.txt");
    std::fs::write(&file, b"hello").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));

    assert!(guard.check_read(&file).is_ok());
}

#[test]
fn read_outside_allowed_root_is_denied() {
    let allowed = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let secret = elsewhere.path().join("secret.txt");
    std::fs::write(&secret, b"secret").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(allowed.path())));

    assert!(guard.check_read(&secret).is_err());
}

/// A guard comparing string prefixes passes this path — it starts with the allowed root —
/// while pointing outside it.
#[test]
fn parent_traversal_cannot_escape_root() {
    let root = tempfile::tempdir().unwrap();
    let inner = root.path().join("work");
    std::fs::create_dir(&inner).unwrap();
    let outside = root.path().join("outside.txt");
    std::fs::write(&outside, b"nope").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(&inner)));

    assert!(
        guard.check_read(&inner.join("../outside.txt")).is_err(),
        "`..` escaped the allowed root"
    );
}

/// The link itself lives in an allowed directory, so only resolving it catches this.
#[cfg(unix)]
#[test]
fn symlink_cannot_escape_root() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let secret = elsewhere.path().join("secret.txt");
    std::fs::write(&secret, b"secret").unwrap();

    let link = root.path().join("innocent.txt");
    std::os::unix::fs::symlink(&secret, &link).unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));

    assert!(
        guard.check_read(&link).is_err(),
        "symlink escaped the allowed root"
    );
}

/// A write targets a file that does not exist yet, so the check can require only the
/// parent to resolve.
#[test]
fn write_to_new_file_in_allowed_root_is_permitted() {
    let root = tempfile::tempdir().unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(vetted(root.path())));

    let new_file = root.path().join("created-later.txt");
    assert!(!new_file.exists());

    assert!(guard.check_write(&new_file).is_ok());
}

#[test]
fn write_to_new_file_outside_allowed_root_is_denied() {
    let root = tempfile::tempdir().unwrap();
    let inner = root.path().join("work");
    std::fs::create_dir(&inner).unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(vetted(&inner)));

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

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));

    assert!(guard.check_read(&file).is_ok());
    assert!(
        guard.check_write(&file).is_err(),
        "read access must not grant write access"
    );
}

/// The agent loop hands the reason to a model, which relays it to whoever asked.
#[test]
fn a_refusal_names_the_grant_that_was_missing() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("notes.txt");
    std::fs::write(&file, b"hello").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));

    let error = guard.check_write(&file).unwrap_err();
    assert!(
        matches!(
            error,
            SandboxError::PathNotAllowed {
                access: Access::Write,
                ..
            }
        ),
        "{error:?}"
    );

    // The path is inside a root, so "every allowed root" would be false of it.
    let message = error.to_string();
    assert!(message.contains("outside every writable root"), "{message}");
    assert!(!message.contains("allowed root"), "{message}");
}

#[test]
fn a_read_refusal_names_the_readable_roots() {
    let allowed = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let secret = elsewhere.path().join("secret.txt");
    std::fs::write(&secret, b"secret").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(allowed.path())));

    let error = guard.check_read(&secret).unwrap_err();
    assert!(
        matches!(
            error,
            SandboxError::PathNotAllowed {
                access: Access::Read,
                ..
            }
        ),
        "{error:?}"
    );
    assert!(
        error.to_string().contains("outside every readable root"),
        "{error}"
    );
}

/// The audit record's reason and the message a caller saw come from one function.
#[test]
fn the_record_and_the_error_cannot_disagree() {
    for access in [Access::Read, Access::Write] {
        let error = SandboxError::PathNotAllowed {
            requested: std::path::PathBuf::from("/nowhere"),
            access,
        };

        assert!(error.to_string().contains(access.outside()), "{error}");
    }
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

/// `canonicalize` fails identically on a nonexistent path and on a dangling symlink, so a
/// guard falling back to the parent approves the link and the write follows it out.
#[cfg(unix)]
#[test]
fn write_to_dangling_symlink_is_denied() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();

    // Target does not exist yet, which is what makes canonicalize fail.
    let outside = elsewhere.path().join("authorized_keys");
    let link = root.path().join("notes.txt");
    std::os::unix::fs::symlink(&outside, &link).unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(vetted(root.path())));

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
    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(vetted(root.path())));

    assert!(guard.check_write(&root.path().join("fresh.txt")).is_ok());
}

/// A *file* is what exercises the per-entry check: `DirEntry::file_type` is lstat-based,
/// so `is_dir()` is false for a directory symlink and the walk never descends into one
/// regardless of the check.
#[cfg(unix)]
#[test]
fn walk_does_not_follow_a_symlink_out_of_the_root() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let secret = elsewhere.path().join("secret.txt");
    std::fs::write(&secret, b"SECRET").unwrap();

    std::os::unix::fs::symlink(&secret, root.path().join("innocent.txt")).unwrap();
    std::fs::write(root.path().join("ours.txt"), b"ours").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));
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

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));
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

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));
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

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));
    let found = guard.walk_readable(root.path(), usize::MAX).unwrap().files;

    assert_eq!(found.len(), 1, "got {found:?}");
    assert!(found[0].ends_with("deep.txt"));
}

#[test]
fn walk_refuses_a_root_outside_the_policy() {
    let allowed = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(allowed.path())));
    assert!(guard.walk_readable(elsewhere.path(), usize::MAX).is_err());
}

/// `canonicalize` fails differently for a missing file (ENOENT), an unreadable parent
/// (EACCES) and a path that resolves but is out of bounds. Passing the difference back
/// turns the guard into a filesystem oracle a prompt-injected model can map the host with.
#[test]
fn refusals_outside_the_policy_are_indistinguishable() {
    let allowed = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let exists = elsewhere.path().join("exists.txt");
    std::fs::write(&exists, b"x").unwrap();
    let missing = elsewhere.path().join("missing.txt");

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(allowed.path())));

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
fn write_refusals_outside_the_policy_look_alike() {
    let allowed = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let exists = elsewhere.path().join("exists.txt");
    std::fs::write(&exists, b"x").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(vetted(allowed.path())));

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

/// The directory to create is the agent's to fix, and the grant already covers it.
#[test]
fn a_missing_write_parent_in_a_grant_is_absent() {
    let root = tempfile::tempdir().unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(vetted(root.path())));

    let error = guard
        .check_write(&root.path().join("nodir/f.txt"))
        .unwrap_err();

    assert!(
        matches!(error, SandboxError::NotFound { .. }),
        "got {error:?}"
    );
    // Naming the leaf tells a tool that creates files it cannot find the one it is creating.
    let message = error.to_string();
    assert!(message.contains("nodir"), "got {message}");
    assert!(!message.contains("f.txt"), "got {message}");
}

/// The gate is a set of errnos: ENOTDIR here, which is #180 one errno over.
#[test]
fn a_path_through_a_file_in_a_grant_is_not_a_refusal() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("notes.txt"), b"x").unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));

    let error = guard
        .check_read(&root.path().join("notes.txt/nested"))
        .unwrap_err();

    assert!(
        matches!(error, SandboxError::NotFound { .. }),
        "got {error:?}"
    );
}

/// The write path resolves the parent, so an absent one answers ENOENT where a present one
/// answers EACCES: the oracle the read path already closes.
#[test]
fn write_to_a_missing_parent_outside_looks_alike() {
    let allowed = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(vetted(allowed.path())));

    let for_existing = guard
        .check_write(&elsewhere.path().join("exists.txt"))
        .unwrap_err()
        .to_string();
    let for_missing = guard
        .check_write(&elsewhere.path().join("nodir/missing.txt"))
        .unwrap_err()
        .to_string();

    assert!(!for_missing.contains("No such file"), "{for_missing}");
    assert_eq!(
        for_existing.replace("exists.txt", "X"),
        for_missing.replace("nodir/missing.txt", "X")
    );
}

/// A refusal and an absence are different next moves: widen the grant, or fix the name.
#[test]
fn a_missing_file_in_a_grant_is_not_a_refusal() {
    let root = tempfile::tempdir().unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));

    let error = guard
        .check_read(&root.path().join("absent.txt"))
        .unwrap_err();

    assert!(
        matches!(error, SandboxError::NotFound { .. }),
        "got {error:?}"
    );
}

/// Absence is reported only where a grant already covers the area.
#[test]
fn a_missing_path_outside_a_grant_is_a_refusal() {
    let allowed = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(allowed.path())));

    let error = guard
        .check_read(&elsewhere.path().join("absent.txt"))
        .unwrap_err();

    assert!(
        matches!(error, SandboxError::PathNotAllowed { .. }),
        "absence leaked outside every grant: {error:?}"
    );
}

/// Containment is tested on a resolved path, so one that will not resolve is inside no
/// root. A loop has no target to conceal and is concealed anyway, the three failures
/// reading alike.
#[cfg(unix)]
#[test]
fn an_unresolvable_path_in_a_grant_is_not_absent() {
    let root = tempfile::tempdir().unwrap();
    let looped = root.path().join("loop");
    std::os::unix::fs::symlink(&looped, &looped).unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));

    let error = guard.check_read(&looped).unwrap_err();

    assert!(
        matches!(error, SandboxError::PathNotAllowed { .. }),
        "got {error:?}"
    );
}

/// A planted symlink would otherwise answer "does this host path exist" for any target:
/// dangling as the link's own absence, resolving as out of bounds. One refusal for both.
#[cfg(unix)]
#[test]
fn a_symlink_out_of_a_grant_conceals_its_target_either_way() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let present = elsewhere.path().join("present.txt");
    std::fs::write(&present, b"x").unwrap();

    let dangling = root.path().join("probe-missing");
    std::os::unix::fs::symlink(elsewhere.path().join("gone.txt"), &dangling).unwrap();
    let resolving = root.path().join("probe-present");
    std::os::unix::fs::symlink(&present, &resolving).unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));

    for probe in [&dangling, &resolving] {
        let error = guard.check_read(probe).unwrap_err();
        assert!(
            matches!(error, SandboxError::PathNotAllowed { .. }),
            "{} leaked its target: {error:?}",
            probe.display()
        );
    }
}

/// Same for a write through a symlinked *parent*, which the leaf guard cannot see: its
/// `symlink_metadata` is on the full path, and that fails outright when the parent dangles.
#[cfg(unix)]
#[test]
fn a_symlinked_parent_out_of_a_grant_conceals_its_target() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    std::fs::create_dir(elsewhere.path().join("there")).unwrap();

    let dangling = root.path().join("to-nowhere");
    std::os::unix::fs::symlink(elsewhere.path().join("gone"), &dangling).unwrap();
    let resolving = root.path().join("to-there");
    std::os::unix::fs::symlink(elsewhere.path().join("there"), &resolving).unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(vetted(root.path())));

    for parent in [&dangling, &resolving] {
        let error = guard.check_write(&parent.join("out.txt")).unwrap_err();
        assert!(
            matches!(error, SandboxError::PathNotAllowed { .. }),
            "{} leaked its target: {error:?}",
            parent.display()
        );
    }
}

/// No symlink, so no target a reason could name: this one keeps `Unresolvable`.
#[cfg(unix)]
#[test]
fn an_unreadable_parent_in_a_grant_stays_unresolvable() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let locked = root.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

    let error = guard.check_read(&locked.join("inner.txt")).unwrap_err();

    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();

    assert!(
        matches!(error, SandboxError::Unresolvable { .. }),
        "got {error:?}"
    );
}

/// The policy already grants this directory, so reporting a file in it absent discloses
/// nothing the caller was not entitled to learn.
#[test]
fn a_missing_file_in_an_allowed_root_says_so() {
    let root = tempfile::tempdir().unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));

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
fn a_missing_file_in_an_allowed_subdirectory_says_so() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("sub")).unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));

    let error = guard
        .check_read(&root.path().join("sub/absent.txt"))
        .unwrap_err()
        .to_string();

    assert!(error.contains("No such file"), "got: {error}");
}

#[test]
fn open_read_returns_a_handle_in_an_allowed_root() {
    use std::io::Read;

    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("notes.txt"), b"hello").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));
    let mut file = guard.open_read(&root.path().join("notes.txt")).unwrap();

    let mut got = String::new();
    file.read_to_string(&mut got).unwrap();
    assert_eq!(got, "hello");
}

#[test]
fn open_read_refuses_a_path_outside_every_root() {
    let allowed = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    std::fs::write(elsewhere.path().join("secret.txt"), b"secret").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(allowed.path())));

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
    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(vetted(root.path())));

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

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));

    assert!(guard.open_write(&root.path().join("notes.txt")).is_err());
    assert_eq!(
        std::fs::read_to_string(root.path().join("notes.txt")).unwrap(),
        "original"
    );
}

/// Matches the `write` tool's replace-the-file semantics: otherwise a shorter write leaves
/// a tail of the old content.
#[test]
fn open_write_truncates_existing_content() {
    use std::io::Write;

    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("existing.txt");
    std::fs::write(&target, b"a much longer original body").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(vetted(root.path())));
    let mut file = guard.open_write(&target).unwrap();
    file.write_all(b"short").unwrap();
    drop(file);

    assert_eq!(std::fs::read_to_string(&target).unwrap(), "short");
}

/// A program needs `Execute` on the binary and `ReadFile` on the libraries its loader
/// pulls in, so execute alone would start nothing; the kernel layer matches, as
/// `AccessFs::from_read` bundles `ReadFile`/`ReadDir` with `Execute`.
#[test]
fn an_execute_grant_permits_reading() {
    let root = tempfile::tempdir().unwrap();
    let program = root.path().join("program");
    std::fs::write(&program, b"#!/bin/sh\nexit 0\n").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read_execute(vetted(root.path())));

    assert!(
        guard.check_read(&program).is_ok(),
        "FsGuard denies a read the kernel layer permits: the two layers disagree"
    );
}

/// The kernel grants `from_read` on that axis and nothing more.
#[test]
fn an_execute_grant_does_not_permit_writing() {
    let root = tempfile::tempdir().unwrap();
    let program = root.path().join("program");
    std::fs::write(&program, b"#!/bin/sh\nexit 0\n").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read_execute(vetted(root.path())));

    assert!(
        guard.check_write(&program).is_err(),
        "an execute grant must not confer write"
    );
}

/// The same claim as the pairs above over [`Axis::ALL`], so an axis added later cannot
/// slip through.
#[test]
fn every_axis_grants_exactly_what_the_table_says() {
    use sandbx_core::Axis;

    for axis in Axis::ALL {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("subject");
        std::fs::write(&file, b"x").unwrap();

        let grants = axis.grants();
        let guard = FsGuard::new(&SandboxPolicy::default().grant(axis, vetted(root.path())));

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

/// `FsGuard::new` returns `Self` rather than a `Result` because a root that has gone is
/// already denied by the check: nothing resolves inside a path that does not resolve, so
/// there is nothing for construction to refuse.
///
/// The root is granted while it exists and removed afterwards, because a grant is pinned to
/// the object it named and so cannot be built over a path that never existed (#212).
#[test]
fn an_unresolvable_root_grants_nothing() {
    let root = tempfile::tempdir().unwrap();
    let absent = root.path().join("granted-then-gone");
    std::fs::create_dir(&absent).unwrap();
    let real = root.path().join("notes.txt");
    std::fs::write(&real, b"hello").unwrap();

    let policy = SandboxPolicy::default()
        .allow_read(vetted(&absent))
        .allow_write(vetted(&absent));
    std::fs::remove_dir(&absent).unwrap();

    let guard = FsGuard::new(&policy);

    assert!(guard.check_read(&absent.join("inside.txt")).is_err());
    assert!(guard.check_write(&absent.join("inside.txt")).is_err());
    // And it did not widen into a sibling that does exist.
    assert!(guard.check_read(&real).is_err());
}

/// The substitution the second half of #212 exists to refuse: a real directory moved onto a
/// granted name, which every spelling comparison agrees with. The refusal has to carry both
/// objects, the operator having one name and two directories to tell apart.
#[test]
fn a_real_directory_put_at_a_granted_name_is_refused() {
    let work = tempfile::tempdir().unwrap();
    let granted = work.path().join("granted");
    let other = work.path().join("other");
    std::fs::create_dir(&granted).unwrap();
    std::fs::create_dir(&other).unwrap();
    std::fs::write(granted.join("notes.txt"), b"hello").unwrap();
    std::fs::write(other.join("notes.txt"), b"planted").unwrap();

    let pin = vetted(&granted);
    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(pin.clone()));
    assert!(
        guard.check_read(&granted.join("notes.txt")).is_ok(),
        "the grant did not work before the substitution, so a refusal after it proves nothing"
    );

    let planted = vetted(&other).object();
    substitute(&granted, &other);

    let error = guard.check_read(&granted.join("notes.txt")).unwrap_err();
    let SandboxError::RootReplaced {
        granted: named,
        vetted: was,
        opened: is,
    } = &error
    else {
        panic!("{error} is not the moved-root refusal");
    };
    assert_eq!(named, pin.path(), "the refusal named another root");
    assert_eq!(*was, pin.object(), "the refusal lost the object it vetted");
    assert_eq!(*is, planted, "the refusal lost the object it found");
}

/// The positive that tells an object comparison from a spelling one: `rename` moves a name
/// and not an inode, so a root that went away and came back is the directory that was vetted.
#[test]
fn a_root_renamed_away_and_back_still_grants() {
    let work = tempfile::tempdir().unwrap();
    let granted = work.path().join("granted");
    let aside = work.path().join("aside");
    std::fs::create_dir(&granted).unwrap();
    let file = granted.join("notes.txt");
    std::fs::write(&file, b"hello").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(&granted)));
    std::fs::rename(&granted, &aside).unwrap();
    std::fs::rename(&aside, &granted).unwrap();

    assert!(
        guard.check_read(&file).is_ok(),
        "the guard compared spellings, not objects: the directory never changed"
    );
}

/// The other root set, through the arm that resolves only the parent — a write names a file
/// that need not exist, so the root is confirmed on the parent and not on the target.
#[test]
fn a_write_to_a_substituted_root_is_refused() {
    let work = tempfile::tempdir().unwrap();
    let granted = work.path().join("granted");
    let other = work.path().join("other");
    std::fs::create_dir(&granted).unwrap();
    std::fs::create_dir(&other).unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(vetted(&granted)));
    assert!(guard.check_write(&granted.join("new.txt")).is_ok());

    substitute(&granted, &other);

    let error = guard.check_write(&granted.join("new.txt")).unwrap_err();
    assert!(
        matches!(error, SandboxError::RootReplaced { .. }),
        "{error} is not the moved-root refusal"
    );
}

/// Both answers come from one function, so the pair cannot become a one-bit oracle for what
/// the substituted directory holds: before the swap the absence is named, after it neither
/// the present name nor the missing one is.
#[test]
fn a_substituted_root_conceals_an_absence() {
    let work = tempfile::tempdir().unwrap();
    let granted = work.path().join("granted");
    let other = work.path().join("other");
    std::fs::create_dir(&granted).unwrap();
    std::fs::create_dir(&other).unwrap();
    std::fs::write(other.join("present.txt"), b"planted").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(&granted)));
    let absent = guard.check_read(&granted.join("present.txt")).unwrap_err();
    assert!(
        matches!(absent, SandboxError::NotFound { .. }),
        "{absent} is not the absence a granted root reports plainly"
    );

    substitute(&granted, &other);

    let present = guard.check_read(&granted.join("present.txt")).unwrap_err();
    let missing = guard.check_read(&granted.join("missing.txt")).unwrap_err();
    assert_eq!(
        present.label(),
        missing.label(),
        "a name under a substituted root reads back differently for being there: \
         {present} against {missing}"
    );
    assert!(
        matches!(present, SandboxError::RootReplaced { .. }),
        "{present} is not the moved-root refusal"
    );
}

/// The one shape that reads back by its resolved path and not its requested one: a link in the
/// substitute leaves every root, so nothing matches it lexically and the commonest refusal
/// answers. Beside an absent name reporting the substitution, that is a bit about what the
/// substitute holds — the oracle the pair above closes, through the one door it does not use.
#[test]
fn a_link_out_of_a_substituted_root_conceals_itself() {
    let work = tempfile::tempdir().unwrap();
    let granted = work.path().join("granted");
    let other = work.path().join("other");
    let outside = work.path().join("outside");
    std::fs::create_dir(&granted).unwrap();
    std::fs::create_dir(&other).unwrap();
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("secret.txt"), b"not the model's").unwrap();
    // Planted in the substitute, so only whoever swapped the root could have put it there.
    std::os::unix::fs::symlink(outside.join("secret.txt"), other.join("link")).unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(&granted)));
    substitute(&granted, &other);

    let link = guard.check_read(&granted.join("link")).unwrap_err();
    let missing = guard.check_read(&granted.join("missing")).unwrap_err();

    assert_eq!(
        link.label(),
        missing.label(),
        "a link out of a substituted root reads back differently for being there: \
         {link} against {missing}"
    );
    assert!(
        matches!(link, SandboxError::RootReplaced { .. }),
        "{link} is not the moved-root refusal"
    );
}

/// The reason above must come off the requested path's own root, not from any root being
/// substituted: a link out of a *confirmed* root is plainly out of bounds, and calling that a
/// substitution would accuse a root that never moved.
#[test]
fn a_link_out_of_a_confirmed_root_is_plainly_outside() {
    let work = tempfile::tempdir().unwrap();
    let granted = work.path().join("granted");
    let outside = work.path().join("outside");
    std::fs::create_dir(&granted).unwrap();
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("secret.txt"), b"not the model's").unwrap();
    std::os::unix::fs::symlink(outside.join("secret.txt"), granted.join("link")).unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(&granted)));
    let error = guard.check_read(&granted.join("link")).unwrap_err();

    assert!(
        matches!(error, SandboxError::PathNotAllowed { .. }),
        "{error} accuses a root that is still the one it was vetted on"
    );
}

/// A write refuses a symlinked leaf on sight, before resolving anything, so that reason has
/// to come after the root's: chosen by what the substitute holds, it answers whether a name in
/// a swapped-in directory is a symlink.
#[test]
fn a_write_to_a_moved_root_outranks_its_leaf() {
    let work = tempfile::tempdir().unwrap();
    let granted = work.path().join("granted");
    let other = work.path().join("other");
    std::fs::create_dir(&granted).unwrap();
    std::fs::create_dir(&other).unwrap();
    std::os::unix::fs::symlink("nowhere", other.join("leaf")).unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(vetted(&granted)));
    let leaf = granted.join("leaf");

    // The same spelling inside the root it was granted on, where the leaf's own reason is the
    // right one: nothing has been substituted for the guard to report instead.
    std::os::unix::fs::symlink("nowhere", &leaf).unwrap();
    let dangling = guard.check_write(&leaf).unwrap_err();
    assert!(
        matches!(dangling, SandboxError::PathNotAllowed { .. }),
        "{dangling} is not the refusal a symlinked leaf gets inside its own root"
    );

    substitute(&granted, &other);

    let moved = guard.check_write(&leaf).unwrap_err();
    assert!(
        matches!(moved, SandboxError::RootReplaced { .. }),
        "{moved} reports the substitute's own leaf instead of the substitution"
    );
    // The pair the label must not tell apart: one name is a symlink under the substitute and
    // the other is not there at all.
    let absent = guard.check_write(&granted.join("absent")).unwrap_err();
    assert_eq!(
        moved.label(),
        absent.label(),
        "a name under a substituted root reads back differently for being a symlink: \
         {moved} against {absent}"
    );
}

/// A symlinked component is refused inside a confirmed root — the concealment rule — so the
/// root has to be measured before the spelling is judged, or the one shape that cannot be
/// concealed is also the one the substitution is never measured for.
#[test]
fn a_moved_root_refuses_alike_through_a_symlink() {
    let work = tempfile::tempdir().unwrap();
    let granted = work.path().join("granted");
    let other = work.path().join("other");
    std::fs::create_dir(&granted).unwrap();
    std::fs::create_dir(&other).unwrap();
    // Dangling, so resolution trips on the link itself and not on what it names.
    std::os::unix::fs::symlink("nowhere", granted.join("link")).unwrap();
    std::os::unix::fs::symlink("nowhere", other.join("link")).unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(&granted)));
    let through = granted.join("link").join("leaf.txt");

    let concealed = guard.check_read(&through).unwrap_err();
    assert!(
        matches!(concealed, SandboxError::PathNotAllowed { .. }),
        "{concealed} is not the refusal a symlinked component gets inside its own root"
    );

    substitute(&granted, &other);

    let moved = guard.check_read(&through).unwrap_err();
    assert!(
        matches!(moved, SandboxError::RootReplaced { .. }),
        "{moved} names the spelling and not the root that was substituted under it"
    );
}

/// `ls`'s only route, and the one wrapper with no `O_NOFOLLOW` form to fall back on.
#[test]
fn a_listing_of_a_substituted_root_is_refused() {
    let work = tempfile::tempdir().unwrap();
    let granted = work.path().join("granted");
    let other = work.path().join("other");
    std::fs::create_dir(&granted).unwrap();
    std::fs::create_dir(&other).unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(&granted)));
    assert!(guard.read_dir(&granted).is_ok());

    substitute(&granted, &other);

    let error = guard.read_dir(&granted).expect_err("a refused listing");
    assert!(
        matches!(error, SandboxError::RootReplaced { .. }),
        "{error} is not the moved-root refusal"
    );
}

/// `grep` and `find`, whose root the walk confirms once for the whole traversal.
#[test]
fn a_walk_of_a_substituted_root_is_refused() {
    let work = tempfile::tempdir().unwrap();
    let granted = work.path().join("granted");
    let other = work.path().join("other");
    std::fs::create_dir(&granted).unwrap();
    std::fs::create_dir(&other).unwrap();
    std::fs::write(other.join("planted.txt"), b"planted").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(&granted)));
    assert!(guard.walk_readable(&granted, 10).is_ok());

    substitute(&granted, &other);

    let error = guard.walk_readable(&granted, 10).unwrap_err();
    assert!(
        matches!(error, SandboxError::RootReplaced { .. }),
        "{error} is not the moved-root refusal"
    );
}

/// A guard that resolved its own roots followed this link and granted its target, so the
/// grant moved to wherever the link had been pointed since the policy was vetted. Both
/// guards come off one policy: the pin is taken once, and the second is built after the swap
/// to stand for any consumer constructing a guard later in the run.
#[cfg(unix)]
#[test]
fn a_root_replaced_by_a_symlink_is_refused() {
    let parent = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let secret = elsewhere.path().join("secret.txt");
    std::fs::write(&secret, b"secret").unwrap();

    let granted = parent.path().join("granted");
    std::fs::create_dir(&granted).unwrap();
    std::fs::write(granted.join("notes.txt"), b"hello").unwrap();
    let policy = SandboxPolicy::default().allow_read(vetted(&granted));
    assert!(
        FsGuard::new(&policy)
            .check_read(&granted.join("notes.txt"))
            .is_ok()
    );

    std::fs::remove_dir_all(&granted).unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), &granted).unwrap();
    let guard = FsGuard::new(&policy);

    let direct = guard.check_read(&secret).unwrap_err();
    assert!(
        matches!(direct, SandboxError::PathNotAllowed { .. }),
        "the link's target became a root of its own: {direct}"
    );
    let through = guard.check_read(&granted.join("secret.txt")).unwrap_err();
    assert!(
        matches!(through, SandboxError::PathNotAllowed { .. }),
        "the grant followed the link: {through}"
    );
}

/// The walk collects every readable path into memory first, so an unbounded tree is
/// unbounded memory. The cap stops the walk rather than trimming the result.
#[test]
fn walk_stops_at_the_file_cap() {
    let root = tempfile::tempdir().unwrap();
    for n in 0..20 {
        std::fs::write(root.path().join(format!("f{n}.txt")), b"x").unwrap();
    }

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));
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

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));
    let walk = guard.walk_readable(root.path(), 10).unwrap();

    assert_eq!(walk.files.len(), 2);
    assert!(!walk.truncated);
}

/// Inferring truncation from `files.len() == max` would report this tree as partial.
#[test]
fn walk_of_exactly_the_cap_is_not_truncated() {
    let root = tempfile::tempdir().unwrap();
    for n in 0..4 {
        std::fs::write(root.path().join(format!("f{n}.txt")), b"x").unwrap();
    }

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(vetted(root.path())));
    let walk = guard.walk_readable(root.path(), 4).unwrap();

    assert_eq!(walk.files.len(), 4);
    assert!(!walk.truncated, "a tree that exactly fits is not partial");
}
