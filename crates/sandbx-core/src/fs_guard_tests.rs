use super::{
    ESCAPED, FsGuard, Openat2, ReadableWalk, UNRESOLVABLE, collapsed, open, openat2_support_from,
    probe_subject, reason,
};
use crate::{Access, SandboxError, SandboxPolicy, VettedPath};
use std::fs::OpenOptions;
use std::os::unix::fs as unix_fs;
use std::path::Path;
use std::{env, fs, io};

/// The relative arm the public tests cannot reach: `set_current_dir` is process-wide.
#[test]
fn a_relative_spelling_collapses_against_the_working_directory() {
    let here = env::current_dir().expect("a working directory");

    assert_eq!(
        collapsed(Path::new("granted/notes.txt")).expect("a working directory"),
        here.join("granted").join("notes.txt")
    );
    assert_eq!(
        collapsed(Path::new("data/../granted/notes.txt")).expect("a working directory"),
        here.join("granted").join("notes.txt")
    );
}

/// Lexically here, through the link's *target* in the kernel — hence both forms are tested.
#[test]
fn a_collapse_is_not_a_canonicalization() {
    assert_eq!(
        collapsed(Path::new("/a/link/../b")).expect("absolute needs no cwd"),
        Path::new("/a/b")
    );
    assert_eq!(
        collapsed(Path::new("/a/./b/")).expect("absolute needs no cwd"),
        Path::new("/a/b")
    );
    // Past the root, where there is nothing left to pop.
    assert_eq!(
        collapsed(Path::new("/../..")).expect("absolute needs no cwd"),
        Path::new("/")
    );
}

#[test]
fn an_absent_approved_path_opens_as_not_found() {
    let root = tempfile::tempdir().unwrap();
    let gone = root.path().join("deleted-after-the-check");

    let error = open(OpenOptions::new().read(true), &gone, &gone, Access::Read).unwrap_err();

    assert!(
        matches!(error, SandboxError::NotFound { .. }),
        "got {error:?}"
    );
}

/// The leaf-swap the `O_NOFOLLOW` flag exists to catch stays a refusal.
#[cfg(unix)]
#[test]
fn a_swapped_leaf_opens_as_unresolvable() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("target.txt");
    fs::write(&target, b"x").unwrap();
    let link = root.path().join("swapped");
    unix_fs::symlink(&target, &link).unwrap();

    let error = open(OpenOptions::new().read(true), &link, &link, Access::Read).unwrap_err();

    assert!(
        matches!(error, SandboxError::Unresolvable { .. }),
        "got {error:?}"
    );
}
/// Both branches of the rooting decision answer alike. No CI runner is below the 5.6
/// `openat2` needs, so the by-path branch is reachable nowhere else — and a fallback no
/// suite exercises is a hole every suite passes.
#[test]
fn both_rootings_answer_alike() {
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("sub")).unwrap();
    fs::write(root.path().join("sub/deep.txt"), b"deep").unwrap();
    fs::write(root.path().join("top.txt"), b"top").unwrap();
    let policy = SandboxPolicy::default()
        .allow_read(VettedPath::vet(root.path()).unwrap())
        .allow_write(VettedPath::vet(root.path()).unwrap());

    let rooted = FsGuard::with_rooting(&policy, None, Openat2::Present);
    let by_path = FsGuard::with_rooting(&policy, None, Openat2::Absent);
    assert!(
        rooted.readable[0].dir.is_some() && by_path.readable[0].dir.is_none(),
        "the two branches must actually differ, or this compares one thing twice"
    );

    let file = root.path().join("top.txt");
    for (label, guard) in [("rooted", &rooted), ("by path", &by_path)] {
        let mut got = String::new();
        guard
            .open_read(&file)
            .unwrap()
            .read_to_string(&mut got)
            .unwrap_or_else(|_| panic!("{label} must read"));
        assert_eq!(got, "top", "{label}");
    }

    let listing = |guard: &FsGuard| {
        let mut names: Vec<_> = guard
            .read_dir(root.path())
            .unwrap()
            .unwrap()
            .entries
            .into_iter()
            .map(|entry| (entry.name, entry.directory))
            .collect();
        names.sort();
        names
    };
    assert_eq!(listing(&rooted), listing(&by_path));

    assert_eq!(
        rooted.walk_readable(root.path(), usize::MAX).unwrap().files,
        by_path
            .walk_readable(root.path(), usize::MAX)
            .unwrap()
            .files,
    );

    let fresh = root.path().join("made.txt");
    for guard in [&rooted, &by_path] {
        fs::remove_file(&fresh).ok();
        guard.open_write(&fresh).unwrap().write_all(b"w").unwrap();
        assert_eq!(fs::read_to_string(&fresh).unwrap(), "w");
    }

    // The shapes a walk root can take that are not a readable directory. These are where
    // the two descents diverged once — the rooted one propagated the open's errno where
    // the by-path one skipped the directory and reported no files — and the divergence
    // showed only here, every other input being a directory that opens.
    let label = |walked: &Result<ReadableWalk, SandboxError>| match walked {
        Ok(walk) => format!("ok:{}", walk.files.len()),
        Err(error) => error.label().to_string(),
    };
    for subject in [&file, &root.path().join("sub")] {
        let unreadable = subject.ends_with("sub");
        if unreadable {
            let mut mode = fs::metadata(subject).unwrap().permissions();
            mode.set_mode(0o000);
            fs::set_permissions(subject, mode).unwrap();
        }

        assert_eq!(
            label(&rooted.walk_readable(subject, usize::MAX)),
            label(&by_path.walk_readable(subject, usize::MAX)),
            "the two descents must answer alike for {}",
            subject.display()
        );

        if unreadable {
            let mut mode = fs::metadata(subject).unwrap().permissions();
            mode.set_mode(0o755);
            fs::set_permissions(subject, mode).unwrap();
        }
    }
}

/// Which errnos are a verdict about `openat2` itself. Only a kernel that does not have
/// it, or does not know the resolve flags, turns rooting off; anything else says nothing
/// about the call and must leave it on, since disabling it for every root on an
/// unrelated errno is a hole both suites pass.
#[test]
fn the_rooting_decision_reads_only_its_own_errnos() {
    for errno in [
        nix::errno::Errno::ENOSYS,
        nix::errno::Errno::EINVAL,
        nix::errno::Errno::E2BIG,
        nix::errno::Errno::EOPNOTSUPP,
    ] {
        assert_eq!(
            openat2_support_from(|| Err(errno)),
            Openat2::Absent,
            "{errno:?} means the kernel lacks openat2"
        );
    }

    for errno in [
        nix::errno::Errno::EACCES,
        nix::errno::Errno::EPERM,
        nix::errno::Errno::ENOENT,
        nix::errno::Errno::EMFILE,
    ] {
        assert_eq!(
            openat2_support_from(|| Err(errno)),
            Openat2::Present,
            "{errno:?} says nothing about openat2 and must not disable rooting"
        );
    }

    assert_eq!(
        openat2_support_from(|| probe_subject().ok_or(nix::errno::Errno::ENOTDIR)),
        Openat2::Present,
        "a kernel that answers must read as present"
    );
}

/// `EXDEV` is the one thing `RESOLVE_BENEATH` refuses that is not an ordinary failure:
/// a `rename(2)` moved a component out from under the root mid-resolution, which is the
/// window #230 closes, caught. It must not read as a dangling link.
///
/// The mapping and not the race: provoking the rename between the kernel's own
/// resolution steps is not something a test can schedule. The errno itself is measured
/// out of band — `RESOLVE_BENEATH` answers `EXDEV` for a `..` escape, an absolute path
/// and a symlink out, on Linux 6.18.
#[test]
fn a_resolution_that_left_the_root_is_not_a_dangling_link() {
    let escaped = io::Error::from_raw_os_error(libc::EXDEV);
    let dangling = io::Error::from_raw_os_error(libc::ELOOP);

    assert_eq!(reason(&escaped), ESCAPED);
    assert_eq!(reason(&dangling), UNRESOLVABLE);
    assert_ne!(
        reason(&escaped),
        reason(&dangling),
        "an operator counting substitution attempts reads these apart"
    );
}

/// `OpenHow` zeroes the mode where `OpenOptions` defaults to `0o666`, so a rooted
/// `O_CREAT` without an explicit mode creates a file nobody can reopen — and the handle
/// already being open hides it from every test that only writes and reads back.
#[test]
fn a_rooted_create_keeps_the_default_mode() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let policy = SandboxPolicy::default().allow_write(VettedPath::vet(root.path()).unwrap());
    let guard = FsGuard::with_rooting(&policy, None, Openat2::Present);
    assert!(
        guard.writable[0].dir.is_some(),
        "this must be the rooted path"
    );

    let made = root.path().join("made.txt");
    drop(guard.open_write(&made).unwrap());

    let mode = fs::metadata(&made).unwrap().permissions().mode() & 0o777;
    assert_ne!(mode, 0, "a mode of 0o000 is the zeroed `OpenHow`: {mode:o}");
    assert_eq!(
        mode,
        0o666 & !umask(),
        "the rooted create must land where `OpenOptions` would: {mode:o}"
    );
}

/// This process's umask, read by setting it and putting it back — the only way libc
/// offers, there being no `getumask`.
fn umask() -> u32 {
    let mode = nix::sys::stat::umask(nix::sys::stat::Mode::empty());
    nix::sys::stat::umask(mode);
    mode.bits()
}
