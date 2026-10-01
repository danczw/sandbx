//! What one axis confers, over `Axis::ALL` and over both target kinds. No
//! filesystem and no policy involved — [`rights_for`](super::rights_for) is pure.

use super::{AccessFs, LATEST_ABI, rights_for};

/// Every right installed is the one the axis table says, not a second
/// opinion about it.
///
/// The tests below pin the three axes that exist today by hand; this one is
/// stated over `Axis::ALL`, so an axis whose rights are never derived — the
/// failure mode of #51, where the flag round-trips perfectly while granting
/// nothing — fails here.
#[test]
fn rights_follow_the_axis_table() {
    for axis in crate::Axis::ALL {
        let grants = axis.grants();
        let rights = rights_for(axis, true, LATEST_ABI);

        assert!(
            !rights.is_empty(),
            "{axis:?} derives no rights at all, so the grant is silently absent"
        );

        for (right, granted, name) in [
            (AccessFs::ReadFile, grants.read, "read"),
            (AccessFs::ReadDir, grants.read, "read"),
            (AccessFs::WriteFile, grants.write, "write"),
            (AccessFs::MakeDir, grants.write, "write"),
            (AccessFs::Execute, grants.execute, "execute"),
        ] {
            assert_eq!(
                rights.contains(right),
                granted,
                "{axis:?} grants {name}={granted}, but the kernel layer \
                 disagrees about {right:?}"
            );
        }
    }
}

/// Every axis keeps its grant on a regular file, minus what a file cannot
/// carry.
///
/// The file column of [`rights_for`](super::rights_for), stated over `Axis::ALL`;
/// why a file cannot carry the rest is documented there.
#[test]
fn rights_for_narrows_a_regular_file() {
    for axis in crate::Axis::ALL {
        let grants = axis.grants();
        let on_dir = rights_for(axis, true, LATEST_ABI);
        let on_file = rights_for(axis, false, LATEST_ABI);

        // Narrowing is an intersection, so a file can never end up with
        // more than the directory case.
        assert!(
            on_dir.contains(on_file),
            "{axis:?} on a file gained a right the directory case did not have"
        );

        // But it must not narrow to nothing: a grant that installs an empty
        // right set is a permission silently absent.
        assert!(
            !on_file.is_empty(),
            "{axis:?} on a file derives no rights at all"
        );

        // The whole file-legal set, spelled out. Checking a sample of
        // dir-only rights would miss the other nine, and deriving the
        // expectation from `from_file(LATEST_ABI)` would restate the
        // implementation — an ABI bump that moved a right between the two
        // sets would pass either way. Written literally, it breaks and
        // forces the review `BASELINE_ABI`'s doc asks for in prose.
        let file_legal = landlock::make_bitflags!(AccessFs::{
            ReadFile | WriteFile | Execute | Truncate | IoctlDev | ResolveUnix
        });
        assert!(
            (on_file & !file_legal).is_empty(),
            "{axis:?} kept {:?} on a regular file; `PathBeneath` would strip it \
             and, under the HardRequirement `apply` sets, fail `add_rule` — so \
             the whole run is refused",
            on_file & !file_legal
        );

        for (right, granted, name) in [
            (AccessFs::ReadFile, grants.read, "read"),
            (AccessFs::WriteFile, grants.write, "write"),
            (AccessFs::Execute, grants.execute, "execute"),
        ] {
            assert_eq!(
                on_file.contains(right),
                granted,
                "{axis:?} grants {name}={granted}, but the file case disagrees \
                 about {right:?}"
            );
        }
    }
}

/// Reading must never confer the right to *run* what it can see.
///
/// `AccessFs::from_read` bundles `Execute` with `ReadFile`/`ReadDir`, so this
/// is a subtraction that has to happen rather than a default (#19).
///
/// This and the two below look like instances of
/// `rights_follow_the_axis_table` and are not: that one reads its expectation
/// out of [`Axis::grants`], so it cannot catch a change to the table's own
/// rows — flip `Axis::Write` to confer execute and it still passes. These
/// three hard-code the answer instead, which is what makes them fail, and
/// `rules::no_combination_of_grants_confers_execute` hard-codes it for the
/// unioned case. Together they are the whole of that coverage; do not fold them
/// into the table-driven ones.
///
/// [`Axis::grants`]: crate::Axis::grants
#[test]
fn a_read_grant_never_carries_execute() {
    for target_is_dir in [true, false] {
        let rights = rights_for(crate::Axis::Read, target_is_dir, LATEST_ABI);
        assert!(
            !rights.contains(AccessFs::Execute),
            "a read grant handed out Execute (target_is_dir={target_is_dir})"
        );
        assert!(rights.contains(AccessFs::ReadFile));
    }
}

/// The execute axis is the only one that carries it.
#[test]
fn only_the_execute_axis_carries_execute() {
    let rights = rights_for(crate::Axis::ReadExecute, true, LATEST_ABI);
    assert!(rights.contains(AccessFs::Execute));
    // Read comes with it by design — see `SandboxPolicy::executable_paths`.
    assert!(rights.contains(AccessFs::ReadFile));
    // But not write.
    assert!(!rights.contains(AccessFs::WriteFile));
}

/// A write grant carries neither read nor execute.
///
/// `SandboxPolicy::writable_paths` promises "writable does not imply
/// readable", and `FsGuard` always kept that promise; the kernel layer did
/// not, because `from_all` includes `ReadFile`/`ReadDir` and only `Execute`
/// was being subtracted. Subtracting the whole read set makes a write-only
/// drop directory genuinely unreadable on both layers (#49).
#[test]
fn a_write_grant_carries_neither_read_nor_execute() {
    let rights = rights_for(crate::Axis::Write, true, LATEST_ABI);
    assert!(rights.contains(AccessFs::WriteFile));
    assert!(
        !rights.contains(AccessFs::ReadFile) && !rights.contains(AccessFs::ReadDir),
        "a write-only grant handed out read, so the drop directory is readable"
    );
    assert!(!rights.contains(AccessFs::Execute));
}
