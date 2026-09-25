//! Public contract of [`FsGuard`]: nothing outside an allowed root is reachable.
//!
//! These go through the public API only — the same surface a consumer has — so
//! a pass here is evidence the boundary actually holds, not that the test could
//! reach internals no real caller can.
// `mkfifo` is spawned to build a test fixture — a named pipe cannot be
// created through std. This is not code executing around the sandbox,
// which is what the workspace ban on `Command::new` exists to stop.
#![allow(clippy::disallowed_methods)]

use sandbx_core::{FsGuard, SandboxPolicy};

/// A path directly inside an allowed root is fine.
#[test]
fn read_inside_allowed_root_is_permitted() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("notes.txt");
    std::fs::write(&file, b"hello").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(root.path())).unwrap();

    assert!(guard.check_read(&file).is_ok());
}

/// Nothing outside the allowed roots is readable.
#[test]
fn read_outside_allowed_root_is_denied() {
    let allowed = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let secret = elsewhere.path().join("secret.txt");
    std::fs::write(&secret, b"secret").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(allowed.path())).unwrap();

    assert!(guard.check_read(&secret).is_err());
}

/// `..` must not walk out of an allowed root.
///
/// A guard comparing string prefixes passes this path — it starts with the
/// allowed root — while actually pointing outside it.
#[test]
fn parent_traversal_cannot_escape_root() {
    let root = tempfile::tempdir().unwrap();
    let inner = root.path().join("work");
    std::fs::create_dir(&inner).unwrap();
    let outside = root.path().join("outside.txt");
    std::fs::write(&outside, b"nope").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(&inner)).unwrap();

    assert!(
        guard.check_read(&inner.join("../outside.txt")).is_err(),
        "`..` escaped the allowed root"
    );
}

/// A symlink inside an allowed root must not grant access to its target.
///
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

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(root.path())).unwrap();

    assert!(
        guard.check_read(&link).is_err(),
        "symlink escaped the allowed root"
    );
}

/// Writes target files that do not exist yet, so the check cannot require the
/// path itself to resolve — only its parent.
#[test]
fn write_to_new_file_in_allowed_root_is_permitted() {
    let root = tempfile::tempdir().unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(root.path())).unwrap();

    let new_file = root.path().join("created-later.txt");
    assert!(!new_file.exists());

    assert!(guard.check_write(&new_file).is_ok());
}

/// A new file's parent is resolved, so `..` cannot escape on the write path
/// either.
#[test]
fn write_to_new_file_outside_allowed_root_is_denied() {
    let root = tempfile::tempdir().unwrap();
    let inner = root.path().join("work");
    std::fs::create_dir(&inner).unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(&inner)).unwrap();

    assert!(
        guard.check_write(&inner.join("../escaped.txt")).is_err(),
        "`..` escaped the allowed root on the write path"
    );
}

/// Read and write are granted separately: a readable root is not writable.
#[test]
fn read_grant_does_not_imply_write() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("notes.txt");
    std::fs::write(&file, b"hello").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(root.path())).unwrap();

    assert!(guard.check_read(&file).is_ok());
    assert!(
        guard.check_write(&file).is_err(),
        "read access must not grant write access"
    );
}

/// A default policy grants no filesystem access at all.
#[test]
fn default_policy_permits_no_path() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("notes.txt");
    std::fs::write(&file, b"hello").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default()).unwrap();

    assert!(guard.check_read(&file).is_err());
    assert!(guard.check_write(&file).is_err());
}

/// A symlink whose target does not exist yet must not be treated as a new file.
///
/// `canonicalize` fails identically on a nonexistent path and on a dangling
/// symlink, so a guard that falls back to resolving only the parent approves the
/// link — and the caller's write then follows it out of the root.
#[cfg(unix)]
#[test]
fn write_to_dangling_symlink_is_denied() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();

    // Target does not exist yet, which is what makes canonicalize fail.
    let outside = elsewhere.path().join("authorized_keys");
    let link = root.path().join("notes.txt");
    std::os::unix::fs::symlink(&outside, &link).unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(root.path())).unwrap();

    assert!(
        guard.check_write(&link).is_err(),
        "approved a dangling symlink pointing outside the allowed root"
    );
    assert!(
        !outside.exists(),
        "the symlink target was created outside the root"
    );
}

/// The case the fallback exists for must keep working: a plain new file.
#[cfg(unix)]
#[test]
fn write_to_new_file_beside_a_symlink_still_works() {
    let root = tempfile::tempdir().unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(root.path())).unwrap();

    assert!(guard.check_write(&root.path().join("fresh.txt")).is_ok());
}

/// A symlink to a *file* outside the root must not be walked into.
///
/// This is the case that actually exercises the per-entry check. A symlink to a
/// *directory* does not: `DirEntry::file_type` is lstat-based, so `is_dir()` is
/// false for it and the walk never descends regardless. Mutation testing showed
/// directory-symlink tests stay green with the check deleted entirely.
#[cfg(unix)]
#[test]
fn walk_does_not_follow_a_symlink_to_a_file_outside_the_root() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let secret = elsewhere.path().join("secret.txt");
    std::fs::write(&secret, b"SECRET").unwrap();

    std::os::unix::fs::symlink(&secret, root.path().join("innocent.txt")).unwrap();
    std::fs::write(root.path().join("ours.txt"), b"ours").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(root.path())).unwrap();
    let found = guard.walk_readable(root.path()).unwrap();

    assert!(
        !found.iter().any(|p| p == &secret),
        "walk followed a symlink to a file outside the root: {found:?}"
    );
    assert_eq!(found.len(), 1, "expected only the in-root file: {found:?}");
}

/// A symlink to a file *inside* the root is still reachable, or the test above
/// would pass on a walk that simply skips every symlink.
#[cfg(unix)]
#[test]
fn walk_includes_a_symlink_to_a_file_inside_the_root() {
    let root = tempfile::tempdir().unwrap();
    let real = root.path().join("real.txt");
    std::fs::write(&real, b"real").unwrap();
    std::os::unix::fs::symlink(&real, root.path().join("alias.txt")).unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(root.path())).unwrap();
    let found = guard.walk_readable(root.path()).unwrap();

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

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(root.path())).unwrap();
    let found = guard.walk_readable(root.path()).unwrap();

    assert!(
        !found.iter().any(|p| p == &fifo),
        "FIFO returned: {found:?}"
    );
    assert_eq!(found.len(), 1, "got {found:?}");
}

/// Subdirectories are descended.
#[test]
fn walk_descends_real_subdirectories() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("sub")).unwrap();
    std::fs::write(root.path().join("sub/deep.txt"), b"d").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(root.path())).unwrap();
    let found = guard.walk_readable(root.path()).unwrap();

    assert_eq!(found.len(), 1, "got {found:?}");
    assert!(found[0].ends_with("deep.txt"));
}

#[test]
fn walk_refuses_a_root_outside_the_policy() {
    let allowed = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(allowed.path())).unwrap();
    assert!(guard.walk_readable(elsewhere.path()).is_err());
}

/// Refusals must not reveal whether a path outside the policy exists.
///
/// `canonicalize` fails differently for a missing file (ENOENT), an
/// unreadable parent (EACCES) and a path that resolves but is out of bounds.
/// Passing those differences to a caller turns the guard into a filesystem
/// oracle: a prompt-injected model can map the host by probing paths and
/// reading the reason back.
#[test]
fn refusals_outside_the_policy_are_indistinguishable() {
    let allowed = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let exists = elsewhere.path().join("exists.txt");
    std::fs::write(&exists, b"x").unwrap();
    let missing = elsewhere.path().join("missing.txt");

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(allowed.path())).unwrap();

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

/// The same for writes, which already behaved this way — pinned so it stays.
#[test]
fn write_refusals_outside_the_policy_are_indistinguishable() {
    let allowed = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let exists = elsewhere.path().join("exists.txt");
    std::fs::write(&exists, b"x").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(allowed.path())).unwrap();

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

/// Inside an allowed root, "no such file" is honest feedback and must survive.
///
/// The policy already grants this directory, so saying a file in it is absent
/// discloses nothing the caller was not entitled to learn — and a model told
/// only "refused" would retry a path it is allowed to use.
#[test]
fn a_missing_file_inside_an_allowed_root_still_says_so() {
    let root = tempfile::tempdir().unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(root.path())).unwrap();

    let error = guard
        .check_read(&root.path().join("absent.txt"))
        .unwrap_err()
        .to_string();

    assert!(
        error.contains("No such file") || error.contains("not found"),
        "an in-root miss should report why: {error}"
    );
}

/// The distinction survives one level down, where the parent is in-root.
#[test]
fn a_missing_file_in_an_allowed_subdirectory_still_says_so() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("sub")).unwrap();
    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(root.path())).unwrap();

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

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(root.path())).unwrap();
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

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(allowed.path())).unwrap();

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
    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(root.path())).unwrap();

    let target = root.path().join("created.txt");
    let mut file = guard.open_write(&target).unwrap();
    file.write_all(b"written").unwrap();
    drop(file);

    assert_eq!(std::fs::read_to_string(&target).unwrap(), "written");
}

/// A read grant must not yield a writable handle.
#[test]
fn open_write_refuses_a_read_only_grant() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("notes.txt"), b"original").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_read(root.path())).unwrap();

    assert!(guard.open_write(&root.path().join("notes.txt")).is_err());
    assert_eq!(
        std::fs::read_to_string(root.path().join("notes.txt")).unwrap(),
        "original"
    );
}

/// `open_write` truncates, matching the `write` tool's replace-the-file
/// semantics — otherwise a shorter write would leave a tail of the old content.
#[test]
fn open_write_truncates_existing_content() {
    use std::io::Write;

    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("existing.txt");
    std::fs::write(&target, b"a much longer original body").unwrap();

    let guard = FsGuard::new(&SandboxPolicy::default().allow_write(root.path())).unwrap();
    let mut file = guard.open_write(&target).unwrap();
    file.write_all(b"short").unwrap();
    drop(file);

    assert_eq!(std::fs::read_to_string(&target).unwrap(), "short");
}
