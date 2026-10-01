//! Building and applying the Landlock filesystem ruleset.
//!
//! The ABI floor and ceiling live here with the ladder between them, because the
//! rights a grant confers depend on which ABI was negotiated — and the three move
//! together. `super::apply` is what installs the result; nothing in this module
//! restricts the calling process.

use crate::SandboxError;

/// The Landlock ABI floor [`apply`](super::apply) refuses to run below, and the ceiling it
/// negotiates up to.
///
/// `SECURITY.md` claims "Landlock, ABI 5 minimum" and refusal to run on a kernel
/// older than 6.10; this pair is the only place that floor is *enforced*. The
/// same number is also stated in prose in `README.md`, in this crate's
/// `Cargo.toml` and in `ci.yml`, and nothing checks those against this value —
/// so they move in the same change.
///
/// ABI 5 is a floor rather than a preference. Landlock leaves any access type
/// *not* in the handled set unrestricted everywhere, so pinning a lower ABI does
/// not enforce less — it leaves whole categories unguarded. That is how
/// `truncate(2)` was once permitted on any file regardless of policy. So
/// [`BASELINE_ABI`] is attached under `CompatLevel::HardRequirement`, making an
/// older kernel a refusal instead of a silent hole.
///
/// [`LATEST_ABI`] is the ceiling of the same argument, not an exception to it.
/// It was once handled best-effort — rights the kernel happened to have enforced,
/// the rest dropped — and that is exactly what made `SECURITY.md`'s "a ruleset
/// the kernel only partly applies is treated as failure" untrue: asking for
/// rights the kernel lacks makes the ruleset `PartiallyEnforced`, so on every
/// kernel below `LATEST_ABI` *every* run was partly enforced, and refusing that
/// would have refused nearly every host. [`negotiated_abi`] instead settles on
/// the newest ABI the kernel will hard-require in full, so nothing is ever
/// dropped and [`enforcement_verdict`] can refuse a partial result.
///
/// Changing either value changes what sandbx promises, so `SECURITY.md` and the
/// kernel floor quoted in `README.md` move in the same change.
pub(crate) const BASELINE_ABI: landlock::ABI = landlock::ABI::V5; // Linux 6.10: Truncate, Refer, IoctlDev

/// Newest ABI [`apply`](super::apply) negotiates for. See [`BASELINE_ABI`].
pub(crate) const LATEST_ABI: landlock::ABI = landlock::ABI::V9; // Linux 6.15: ResolveUnix

/// Every ABI [`negotiated_abi`] will settle for, newest first.
///
/// Spans [`LATEST_ABI`] down to [`BASELINE_ABI`] and stops there: below the
/// baseline is a refusal, not a lower rung. Written out rather than derived
/// because `ABI` is a closed enum with no iterator and no arithmetic — and a
/// literal ladder is the thing an ABI bump must be forced to edit, next to the
/// two constants that bound it.
const NEGOTIABLE_ABI: [landlock::ABI; 5] = [
    LATEST_ABI,
    landlock::ABI::V8,
    landlock::ABI::V7,
    landlock::ABI::V6,
    BASELINE_ABI,
];

/// The Landlock rights an axis grants on a target, narrowed to what that target
/// can carry.
///
/// Pure and total: three axes times a file or a directory is six answers, every
/// one of them assertable with no privilege and no filesystem. The narrowing used
/// to sit in [`fs_rules`] next to the `is_dir()` that drives it, which fused the
/// decision to a probe and so made the file case reachable only by creating a
/// real file on disk (#52).
///
/// Derived from [`Axis::grants`], so a new axis needs no edit here. Before this
/// derived, the axes were a literal list of `(paths, rights)` pairs, and an axis
/// left out of that list did not fail to compile: its paths were never iterated,
/// no rule was installed for them, and the grant was silently absent (#51).
///
/// The three primitives, and why each is a subtraction rather than a plain set:
///
/// - **read** is `from_read` minus `Execute`. `from_read` bundles `Execute` in
///   with `ReadFile`/`ReadDir`, so granting it raw would hand out the right to
///   *run* whatever the path contains, which no axis but `ReadExecute` says (#19).
/// - **write** is `from_all` minus the whole read set, not just `Execute`.
///   `from_all` includes `ReadFile`/`ReadDir`, so taking only `Execute` away left
///   a write grant conferring read at the kernel while `FsGuard` refused it —
///   one policy, two answers, and the write-only drop directory
///   `writable_paths` promises was readable in the child (#49).
/// - **execute** is the single bit, which is why it can be added back on top of
///   read without widening anything else.
///
/// Directory-only rights (`ReadDir`, `MakeDir`, `Refer`, …) are invalid on a
/// regular file, so a policy naming one must have its rights narrowed to what the
/// target can carry. Intersecting rather than substituting keeps that a
/// restriction: a file can never end up with more than the directory case.
///
/// What makes the narrowing load-bearing is *not* that the kernel refuses an
/// invalid rule — the `landlock` crate never lets the kernel see one. `PathBeneath`
/// stats the fd and strips the dir-only bits itself (its own comment: "Linux would
/// return EINVAL"), reporting `CompatResult::Partial`. Under `BestEffort`, which is
/// the level [`apply`](super::apply) leaves set, `add_rule` then returns `Ok` and the ruleset
/// degrades to `RulesetStatus::PartiallyEnforced` — which [`apply`](super::apply) accepts, since
/// it refuses only `NotEnforced`. Verified against landlock 0.4.7 on a live kernel:
/// `WriteFile | MakeDir | RemoveDir` on a regular file installs silently. So
/// dropping this intersection would not fail; it would quietly degrade every
/// regular-file rule, which is why `rights_for_narrows_a_regular_file` pins the
/// file-legal set literally rather than trusting a refusal.
///
/// [`Axis::grants`]: crate::Axis::grants
fn rights_for(
    axis: crate::Axis,
    target_is_dir: bool,
    abi: landlock::ABI,
) -> landlock::BitFlags<landlock::AccessFs> {
    use landlock::{Access, AccessFs};

    let read_rights = AccessFs::from_read(abi) & !AccessFs::Execute;
    let write_rights = AccessFs::from_all(abi) & !AccessFs::from_read(abi);

    // Destructured, not read field by field — see `Grants`.
    let crate::Grants {
        read,
        write,
        execute,
    } = axis.grants();

    let mut rights = landlock::BitFlags::EMPTY;

    if read {
        rights |= read_rights;
    }
    if write {
        rights |= write_rights;
    }
    if execute {
        rights |= AccessFs::Execute;
    }

    if target_is_dir {
        rights
    } else {
        rights & AccessFs::from_file(abi)
    }
}

/// The Landlock rules [`apply`](super::apply) will install, as `(axis, path, rights)`, one per
/// grant.
///
/// Split out so the whole filesystem mapping can be asserted without root, a
/// network namespace or a Landlock-capable kernel — `apply` itself needs all
/// three, which is why it went untested for so long (#52). The only thing this
/// touches outside the policy is whether each path is a directory, and that is
/// precisely what decides the narrowing below.
///
/// What a grant confers is [`rights_for`]'s business; all this adds is the one
/// probe that decision needs — whether the target is a directory.
///
/// `is_dir()` reports `false` for every error it meets, which would silently drop
/// directory-only rights. That is latent rather than live: a path `is_dir()` could
/// not inspect — a dangling symlink, an unsearchable parent — is also a path
/// [`apply`](super::apply)'s next line cannot open, so `PathFd::new` turns it into a refusal
/// before the narrowed rule reaches the kernel. Propagating it here would add a
/// `Result` to the seam for an error the following line already catches.
///
/// A path that changes kind between the probe and the open narrows in both
/// directions rather than widening: a directory taken for a file loses
/// directory-only rights here, and a file taken for a directory loses them at
/// `add_rule`, where `PathBeneath` strips what a file cannot hold. Neither is a
/// refusal — the second degrades the ruleset to `PartiallyEnforced`, which
/// [`apply`](super::apply) accepts — but neither grants anything the policy did not name.
///
/// The axis rides along even though [`apply`](super::apply) has no use for it. Landlock *unions*
/// the rules it is given for a path, so a tuple of just `(path, rights)` is not
/// the effective right set for any path named on two axes — and `sandbx
/// --allow-write` names one on two axes every time. Carrying the axis keeps both
/// questions answerable: what one grant confers, and what the kernel will enforce
/// once the overlapping grants are unioned (#52).
///
/// Ordered `(axis, path, ..)` after [`SandboxPolicy::granted_paths`], the pairs
/// this is an extension of.
///
/// [`SandboxPolicy::granted_paths`]: crate::SandboxPolicy::granted_paths
pub(super) fn fs_rules(
    policy: &crate::SandboxPolicy,
    abi: landlock::ABI,
) -> Vec<(
    crate::Axis,
    &std::path::Path,
    landlock::BitFlags<landlock::AccessFs>,
)> {
    policy
        .granted_paths()
        .map(|(axis, path)| (axis, path, rights_for(axis, path.is_dir(), abi)))
        .collect()
}

/// The newest ABI this kernel will hard-require, at or above [`BASELINE_ABI`].
///
/// Replaces the old best-effort arm, and the reason is [`enforcement_verdict`].
/// Asking for `LATEST_ABI` best-effort meant the kernel silently dropped whatever
/// it did not have, which made the ruleset `PartiallyEnforced` on every kernel
/// older than the newest ABI this crate knows — a verdict that cannot be refused
/// without refusing nearly every host. Asking only for what the kernel confirms
/// it handles makes full enforcement the normal outcome, so partial enforcement
/// becomes the anomaly it is documented to be.
///
/// Probing with `create()` is deliberate: it builds a ruleset without applying it,
/// so this walks the ladder in one process and nothing is restricted until
/// [`apply`](super::apply) calls `restrict_self`. The kernel's own version syscall would be
/// cheaper, but it is `unsafe` and `landlock` keeps its wrapper private — and a
/// probe that asks the same question the real call will ask cannot disagree with
/// it, which the duplicated ABI floor behind `d4676cc` is the argument for.
///
/// A kernel below [`BASELINE_ABI`] falls off the end and is refused, which is the
/// floor that constant documents.
pub(super) fn negotiated_abi() -> Result<landlock::ABI, SandboxError> {
    use landlock::{Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetError};

    for abi in NEGOTIABLE_ABI {
        let built = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(abi))
            .and_then(|ruleset| ruleset.create());

        match built {
            Ok(_) => return Ok(abi),
            // The one error that is an ABI verdict: under `HardRequirement`,
            // `handle_access` refuses and names the rights this kernel does not
            // have (`partially incompatible access-rights: .. ResolveUnix`). Only
            // this steps down a rung.
            Err(RulesetError::HandleAccesses(_)) => continue,
            // Anything else says nothing about which ABI the kernel has. Stepping
            // down on it would hand back a lower ABI than the kernel supports, and
            // every right above it would then go unhandled — which Landlock leaves
            // unrestricted everywhere. That is the silent hole `BASELINE_ABI`
            // exists to prevent, so a non-verdict error is a refusal.
            Err(error) => return Err(landlock_failed(error)),
        }
    }

    Err(SandboxError::Unsupported {
        detail: "kernel does not support the Landlock baseline this build \
                 requires (ABI 5, Linux 6.10); refusing to run unconfined",
    })
}

/// Accept only a ruleset the kernel enforces in full.
///
/// `SECURITY.md` promises that a partly applied ruleset is treated as failure,
/// and a partly applied ruleset is one where Landlock left some requested access
/// type unhandled — which leaves that type unrestricted everywhere, the same
/// silent hole [`BASELINE_ABI`] describes. So there is nothing to accept here but
/// full enforcement.
///
/// Total over `RulesetStatus` rather than a comparison against one variant: that
/// is what the old `== NotEnforced` check was, and it let `PartiallyEnforced`
/// through for as long as it existed. A variant added by a future landlock
/// release now fails to compile instead of landing in an accepting arm.
pub(super) fn enforcement_verdict(status: landlock::RulesetStatus) -> Result<(), SandboxError> {
    use landlock::RulesetStatus;

    match status {
        RulesetStatus::FullyEnforced => Ok(()),
        RulesetStatus::PartiallyEnforced => Err(SandboxError::Unsupported {
            detail: "kernel enforced only part of the ruleset; some access type \
                     is unrestricted, so the sandbox would not hold",
        }),
        RulesetStatus::NotEnforced => Err(SandboxError::Unsupported {
            detail: "kernel accepted the ruleset but enforced none of it",
        }),
    }
}

pub(super) fn landlock_failed(source: impl std::fmt::Display) -> SandboxError {
    // Carry the kernel's own reason: "refused" without a cause is unactionable
    // for whoever has to work out which path or access right it objected to.
    SandboxError::Landlock {
        detail: source.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SandboxPolicy;
    use landlock::AccessFs;

    /// Keep the returned handle bound for the whole test: dropping it deletes
    /// the directory, and `fs_rules` would then take its regular-file branch.
    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// A regular file, since files and directories take different rights.
    fn plain_file(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let file = dir.path().join("plain.txt");
        std::fs::write(&file, b"x").unwrap();
        file
    }

    /// The rule `axis` produced for `path`.
    ///
    /// Keyed by both, because a path may be granted on more than one axis and the
    /// rules are then separate permissions. Still insists on exactly one match,
    /// so a test cannot quietly assert against a duplicate grant it did not mean.
    fn rule(
        policy: &SandboxPolicy,
        axis: crate::Axis,
        path: &std::path::Path,
    ) -> landlock::BitFlags<AccessFs> {
        let matches: Vec<_> = fs_rules(policy, LATEST_ABI)
            .into_iter()
            .filter(|(a, p, _)| *a == axis && *p == path)
            .map(|(_, _, rights)| rights)
            .collect();

        assert_eq!(
            matches.len(),
            1,
            "expected exactly one {axis:?} rule for {}, got {}",
            path.display(),
            matches.len()
        );
        matches[0]
    }

    /// Every right the rules name for this exact path, unioned the way Landlock
    /// unions them.
    ///
    /// Matches on the path as spelled, where the kernel merges per inode — so two
    /// grants reaching one inode by different spellings (`/usr/bin` and
    /// `/usr/bin/`) are unioned there and counted apart here. Fine for the tests
    /// below, which name one path one way; the gap is a reason not to read this as
    /// the kernel's own answer for an arbitrary policy.
    fn union(policy: &SandboxPolicy, path: &std::path::Path) -> landlock::BitFlags<AccessFs> {
        fs_rules(policy, LATEST_ABI)
            .into_iter()
            .filter(|(_, candidate, _)| *candidate == path)
            .fold(landlock::BitFlags::EMPTY, |union, (_, _, rights)| {
                union | rights
            })
    }

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
    /// The file column of [`rights_for`], stated over `Axis::ALL`; why a file
    /// cannot carry the rest is documented there.
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
                "{axis:?} kept {:?} on a regular file; `PathBeneath` would strip \
                 it and silently degrade the ruleset to PartiallyEnforced",
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
    /// `no_combination_of_grants_confers_execute` hard-codes it for the unioned
    /// case. Together they are the whole of that coverage; do not fold them into
    /// the table-driven ones.
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

    /// Directory-only rights are invalid on a regular file, and the kernel
    /// rejects the whole ruleset if one is attached to it — so a file rule must
    /// come out narrowed.
    #[test]
    fn a_rule_on_a_regular_file_drops_directory_only_rights() {
        let dir = tempdir();
        let file = plain_file(&dir);
        let policy = SandboxPolicy::default()
            .allow_write(dir.path())
            .allow_write(&file);

        let on_dir = rule(&policy, crate::Axis::Write, dir.path());
        let on_file = rule(&policy, crate::Axis::Write, &file);

        assert!(
            on_dir.contains(AccessFs::MakeDir),
            "a directory should keep directory-only rights"
        );
        assert!(
            !on_file.contains(AccessFs::MakeDir),
            "a regular file kept a directory-only right, which invalidates the ruleset"
        );
        // Narrowing is an intersection, so the file can never gain anything the
        // directory case did not already have.
        assert!(on_dir.contains(on_file));
    }

    /// Two grants on one path stay two rules, each carrying its own axis's
    /// rights and nothing of the other's.
    ///
    /// `sandbx --allow-write` grants read *and* write on the same path, so this
    /// is the ordinary case rather than a contrived one. Keyed by path alone the
    /// seam could not say which axis produced which rule, and the only honest
    /// thing a helper could do was refuse to answer — so the two grants were not
    /// separately assertable in exactly the case where they overlap (#52).
    #[test]
    fn a_path_granted_on_two_axes_keeps_one_rule_per_axis() {
        let dir = tempdir();
        let policy = SandboxPolicy::default()
            .allow_read(dir.path())
            .allow_write(dir.path());

        let read = rule(&policy, crate::Axis::Read, dir.path());
        let write = rule(&policy, crate::Axis::Write, dir.path());

        assert!(
            read.contains(AccessFs::ReadDir) && !read.contains(AccessFs::WriteFile),
            "the read grant picked up write from the write grant on the same path"
        );
        assert!(
            write.contains(AccessFs::WriteFile) && !write.contains(AccessFs::ReadDir),
            "the write grant picked up read from the read grant on the same path"
        );
    }

    /// Default-deny: nothing granted means nothing installed.
    #[test]
    fn a_policy_with_no_paths_produces_no_rules() {
        assert!(fs_rules(&SandboxPolicy::default(), LATEST_ABI).is_empty());
    }

    /// One rule per *grant*, not per path: a path granted on two axes yields two
    /// rules, which the kernel unions. A grant dropped here is a permission the
    /// command silently does not get.
    #[test]
    fn every_grant_produces_a_rule_even_for_a_repeated_path() {
        let dir = tempdir();
        let file = plain_file(&dir);
        let policy = SandboxPolicy::default()
            .allow_read(&file)
            .allow_write(dir.path())
            .allow_read_execute(dir.path());

        assert_eq!(fs_rules(&policy, LATEST_ABI).len(), 3);
    }

    /// No combination of grants confers execute.
    ///
    /// `SECURITY.md`'s headline claim, asked in the form it actually takes:
    /// Landlock *unions* the rules it holds for a path, so where two grants
    /// overlap no single rule is the answer. Read plus write on one directory is
    /// the case that matters — it is what `sandbx --allow-write` produces — and
    /// until the seam carried the axis the union could not be asked for at all
    /// (#52).
    ///
    /// Stated over the powerset of `Axis::ALL`, since a policy may grant any
    /// combination on one path. The expectation is deliberately *not* read off
    /// [`Axis::grants`]: naming `ReadExecute` literally is what makes this catch
    /// a table row that starts conferring execute, where an expectation derived
    /// from the table would move with the change and pass. A fourth axis that
    /// confers execute therefore fails here — which is the review that
    /// `SECURITY.md`'s claim should force, not an edit to make quietly.
    ///
    /// [`Axis::grants`]: crate::Axis::grants
    #[test]
    fn no_combination_of_grants_confers_execute() {
        let dir = tempdir();

        for mask in 0..(1u32 << crate::Axis::ALL.len()) {
            let axes: Vec<_> = crate::Axis::ALL
                .into_iter()
                .enumerate()
                .filter(|(index, _)| mask & (1 << index) != 0)
                .map(|(_, axis)| axis)
                .collect();

            let policy = axes.iter().fold(SandboxPolicy::default(), |policy, &axis| {
                policy.grant(axis, dir.path())
            });

            assert_eq!(
                union(&policy, dir.path()).contains(AccessFs::Execute),
                axes.contains(&crate::Axis::ReadExecute),
                "{axes:?} on one path: execute must come from ReadExecute and \
                 nothing else"
            );
        }
    }

    /// The negotiable ladder spans exactly the two documented constants.
    ///
    /// Its ends are [`LATEST_ABI`] and [`BASELINE_ABI`] by construction. What
    /// construction cannot pin is the order and the rungs between them: `ABI` is
    /// a closed enum with no iterator and no arithmetic, so the interior is
    /// hand-written, and `negotiated_abi` takes the first rung that works and
    /// calls it the highest the kernel has. Out of order, that is simply wrong —
    /// it would settle for a lower ABI than available and leave the rights above
    /// it unrequested, which is the silent hole `BASELINE_ABI`'s doc describes.
    /// A gap would skip an ABI the kernel could have enforced in full.
    #[test]
    fn the_abi_ladder_descends_without_gaps() {
        for pair in NEGOTIABLE_ABI.windows(2) {
            assert_eq!(
                pair[0] as i32 - 1,
                pair[1] as i32,
                "{:?} and {:?} are out of order or have a gap between them",
                pair[0],
                pair[1]
            );
        }
    }

    /// Only a fully enforced ruleset is accepted.
    ///
    /// `SECURITY.md` claims "a ruleset the kernel only partly applies is treated
    /// as failure", and until now that was false: the check was
    /// `== NotEnforced`, so `PartiallyEnforced` passed. That was not a corner
    /// case — `apply` asked for `LATEST_ABI` best-effort, so on every kernel
    /// below the newest ABI this crate knows, *every* run was partly enforced and
    /// accepted. Partial enforcement means Landlock left some requested access
    /// type unhandled, and an unhandled access type is unrestricted everywhere —
    /// the same silent hole `BASELINE_ABI`'s doc describes for a pinned-low ABI.
    ///
    /// Total over the enum rather than a comparison, so a status added by a future
    /// landlock release fails to compile here instead of falling through to the
    /// accepting arm.
    #[test]
    fn only_full_enforcement_is_accepted() {
        use landlock::RulesetStatus;

        assert!(enforcement_verdict(RulesetStatus::FullyEnforced).is_ok());

        for status in [RulesetStatus::PartiallyEnforced, RulesetStatus::NotEnforced] {
            let named = format!("{status:?}");
            assert!(
                enforcement_verdict(status).is_err(),
                "{named} was accepted, so the sandbox runs with a hole in it"
            );
        }
    }
}
