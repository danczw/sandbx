//! What one axis confers, over `Axis::ALL` and over both target kinds. No filesystem and
//! no policy involved — [`rights_for`](super::rights_for) is pure.

use super::{AccessFs, BASELINE_ABI, LATEST_ABI, rights_for};

/// Stated over `Axis::ALL`, so an axis whose rights are never derived — a flag that
/// round-trips while granting nothing — fails here. The tests below pin today's three
/// axes by hand.
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

/// The file column of [`rights_for`](super::rights_for), stated over `Axis::ALL`; why a
/// file cannot carry the rest is documented there.
#[test]
fn rights_for_narrows_a_regular_file() {
    for axis in crate::Axis::ALL {
        let grants = axis.grants();
        let on_dir = rights_for(axis, true, LATEST_ABI);
        let on_file = rights_for(axis, false, LATEST_ABI);

        // Narrowing is an intersection, so a file can never end up with more than the
        // directory case.
        assert!(
            on_dir.contains(on_file),
            "{axis:?} on a file gained a right the directory case did not have"
        );

        // But not to nothing: an empty right set is a permission silently absent.
        assert!(
            !on_file.is_empty(),
            "{axis:?} on a file derives no rights at all"
        );

        // The whole file-legal set, spelled out: a sample would miss the other nine, and
        // deriving it from `from_file(LATEST_ABI)` would move with the ABI bump this is
        // meant to catch.
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

/// Reading must never confer the right to *run* what it can see: `AccessFs::from_read`
/// bundles `Execute` with `ReadFile`/`ReadDir`, so this is a subtraction that has to
/// happen rather than a default.
///
/// Not an instance of `rights_follow_the_axis_table`: that one reads its expectation out
/// of [`Axis::grants`], so flipping `Axis::Write` to confer execute still passes it. This,
/// the two below and `rules::no_combination_of_grants_confers_execute` hard-code the
/// answer and are the whole of that coverage.
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

#[test]
fn only_the_execute_axis_carries_execute() {
    let rights = rights_for(crate::Axis::ReadExecute, true, LATEST_ABI);
    assert!(rights.contains(AccessFs::Execute));
    // Read comes with it by design — see `SandboxPolicy::executable_paths`.
    assert!(rights.contains(AccessFs::ReadFile));
    // But not write.
    assert!(!rights.contains(AccessFs::WriteFile));
}

/// Each axis's whole right set on a directory, spelled out at both ends of the negotiable
/// range. Every other assertion here names rights one at a time, and only the five
/// [`Axis::grants`](crate::Axis::grants) has a word for; `AccessFs` has seventeen
/// variants, so twelve would otherwise be pinned by nothing.
///
/// `write` is the sharpest case, being defined by subtraction — `from_all` minus
/// `from_read` — so every right a new ABI adds to the write half joins every
/// `--allow-write` grant. At `LATEST_ABI` that is already two rights beyond writing bytes:
/// `IoctlDev` (device ioctls on a node beneath the path) and `ResolveUnix` (`connect(2)`
/// to a pathname socket beneath it, which `SECURITY.md` treats as seccomp's business).
/// Pinning `ABI::V1` once left `truncate(2)` unguarded on every file regardless of policy.
///
/// Spelled out rather than derived from `from_all`/`from_read`, which would move with the
/// bump it is meant to catch. Both ends are pinned because both are claims — [`BASELINE_ABI`]
/// is what sandbx refuses to run below, [`LATEST_ABI`] the ceiling it negotiates up to —
/// and in one test, so an intentional bump has one place to edit.
#[test]
fn each_axis_confers_exactly_the_documented_set() {
    // Only the write axis differs across the range: `ResolveUnix` arrives in V9, and it
    // is a write-side right.
    let expected = [
        (
            crate::Axis::Read,
            landlock::make_bitflags!(AccessFs::{ReadFile | ReadDir}),
            landlock::make_bitflags!(AccessFs::{ReadFile | ReadDir}),
        ),
        (
            crate::Axis::Write,
            landlock::make_bitflags!(AccessFs::{
                WriteFile | RemoveDir | RemoveFile | MakeChar | MakeDir | MakeReg | MakeSock
                | MakeFifo | MakeBlock | MakeSym | Refer | Truncate | IoctlDev
            }),
            landlock::make_bitflags!(AccessFs::{
                WriteFile | RemoveDir | RemoveFile | MakeChar | MakeDir | MakeReg | MakeSock
                | MakeFifo | MakeBlock | MakeSym | Refer | Truncate | IoctlDev | ResolveUnix
            }),
        ),
        (
            crate::Axis::ReadExecute,
            landlock::make_bitflags!(AccessFs::{Execute | ReadFile | ReadDir}),
            landlock::make_bitflags!(AccessFs::{Execute | ReadFile | ReadDir}),
        ),
    ];

    // Every axis has a row, so a new one cannot be added without one.
    assert_eq!(expected.len(), crate::Axis::ALL.len());

    for (axis, at_baseline, at_latest) in expected {
        assert_eq!(
            rights_for(axis, true, BASELINE_ABI),
            at_baseline,
            "{axis:?} changed shape at the ABI floor; every grant on it moved too"
        );
        assert_eq!(
            rights_for(axis, true, LATEST_ABI),
            at_latest,
            "{axis:?} changed shape at the ABI ceiling; every grant on it moved too"
        );
    }
}

/// `SandboxPolicy::writable_paths` promises "writable does not imply readable". `from_all`
/// includes `ReadFile`/`ReadDir`, so subtracting only `Execute` left the kernel layer
/// granting read where `FsGuard` refused it; subtracting the whole read set makes a
/// write-only drop directory unreadable on both layers.
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
