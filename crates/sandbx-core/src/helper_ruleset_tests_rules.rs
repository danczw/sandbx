//! The mapping itself: one rule per grant, each narrowed to its target, and what the kernel
//! ends up enforcing once overlapping grants are unioned.
//!
//! Asked through [`requested_at`] rather than `fs_rules`, because that is what `apply`
//! installs — the wrapper is where a dropped grant or a re-fused narrowing would hide.

use super::{AccessFs, BASELINE_ABI, LATEST_ABI, SandboxPolicy, requested_at};
use crate::VettedPath;

/// Keep the returned handle bound for the whole test: dropping it deletes the directory,
/// and `fs_rules` would then take its regular-file branch.
fn tempdir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

/// The directory's own resolved path, which is what a grant on it carries — `vet` resolves,
/// so a spelling reaching `/tmp` through a symlink is not the one the rules are keyed by.
fn root(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path().canonicalize().unwrap()
}

/// A regular file, since files and directories take different rights.
fn plain_file(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let file = root(dir).join("plain.txt");
    std::fs::write(&file, b"x").unwrap();
    file
}

/// `path`, pinned to the object it names — the only shape a grant takes.
fn vetted(path: impl AsRef<std::path::Path>) -> VettedPath {
    VettedPath::vet(path).expect("an existing path to pin the grant to")
}

/// The rule `axis` produced for `path`.
///
/// Keyed by both, because one path may be granted on several axes as separate rules.
/// Insists on exactly one match, so a test cannot assert against a duplicate grant.
fn rule(
    policy: &SandboxPolicy,
    axis: crate::Axis,
    path: &std::path::Path,
) -> landlock::BitFlags<AccessFs> {
    let matches: Vec<_> = requested_at(policy, LATEST_ABI)
        .rules
        .into_iter()
        .filter(|(a, granted, _)| *a == axis && granted.path() == path)
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

/// Every right the rules name for this exact path, unioned the way Landlock unions them.
///
/// Matches on the path as spelled, where the kernel merges per inode — so two grants reaching
/// one inode by different spellings (`/usr/bin` and `/usr/bin/`) are unioned there and counted
/// apart here. Fine for the tests below, which name one path one way.
fn union(
    policy: &SandboxPolicy,
    path: &std::path::Path,
    abi: landlock::ABI,
) -> landlock::BitFlags<AccessFs> {
    requested_at(policy, abi)
        .rules
        .into_iter()
        .filter(|(_, candidate, _)| candidate.path() == path)
        .fold(landlock::BitFlags::EMPTY, |union, (_, _, rights)| {
            union | rights
        })
}

/// Directory-only rights are invalid on a regular file, and the kernel rejects the whole
/// ruleset if one is attached to it — so a file rule must come out narrowed.
#[test]
fn a_file_rule_drops_directory_only_rights() {
    let dir = tempdir();
    let root = root(&dir);
    let file = plain_file(&dir);
    let policy = SandboxPolicy::default()
        .allow_write(vetted(&root))
        .allow_write(vetted(&file));

    let on_dir = rule(&policy, crate::Axis::Write, &root);
    let on_file = rule(&policy, crate::Axis::Write, &file);

    assert!(
        on_dir.contains(AccessFs::MakeDir),
        "a directory should keep directory-only rights"
    );
    assert!(
        !on_file.contains(AccessFs::MakeDir),
        "a regular file kept a directory-only right, which invalidates the ruleset"
    );
    // An intersection, so the file can never hold more than the directory case.
    assert!(on_dir.contains(on_file));
}

/// Two grants on one path stay two rules, each carrying its own axis's rights and nothing of
/// the other's. The ordinary case: `sandbx --allow-write` grants read *and* write on one path.
#[test]
fn a_path_granted_on_two_axes_keeps_one_rule_per_axis() {
    let dir = tempdir();
    let root = root(&dir);
    let policy = SandboxPolicy::default()
        .allow_read(vetted(&root))
        .allow_write(vetted(&root));

    let read = rule(&policy, crate::Axis::Read, &root);
    let write = rule(&policy, crate::Axis::Write, &root);

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
    assert!(
        requested_at(&SandboxPolicy::default(), LATEST_ABI)
            .rules
            .is_empty()
    );
}

/// One rule per *grant*, not per path: a path granted on two axes yields two rules, which the
/// kernel unions. A grant dropped here is a permission the command silently does not get.
#[test]
fn every_grant_produces_a_rule_even_when_repeated() {
    let dir = tempdir();
    let root = root(&dir);
    let file = plain_file(&dir);
    let policy = SandboxPolicy::default()
        .allow_read(vetted(&file))
        .allow_write(vetted(&root))
        .allow_read_execute(vetted(&root));

    assert_eq!(requested_at(&policy, LATEST_ABI).rules.len(), 3);
}

/// `SECURITY.md`'s headline claim, asked in the form it takes: Landlock *unions* the rules it
/// holds for a path, so where two grants overlap no single rule is the answer. Stated over the
/// powerset of `Axis::ALL`, since a policy may grant any combination on one path.
///
/// The expectation names `ReadExecute` literally rather than reading
/// [`Axis::grants`](crate::Axis::grants), so a table row that starts conferring execute fails
/// here instead of moving the expectation with it.
#[test]
fn no_combination_of_grants_confers_execute() {
    let dir = tempdir();
    let root = root(&dir);

    for mask in 0..(1u32 << crate::Axis::ALL.len()) {
        let axes: Vec<_> = crate::Axis::ALL
            .into_iter()
            .enumerate()
            .filter(|(index, _)| mask & (1 << index) != 0)
            .map(|(_, axis)| axis)
            .collect();

        let policy = axes.iter().fold(SandboxPolicy::default(), |policy, &axis| {
            policy.grant(axis, vetted(&root))
        });

        assert_eq!(
            union(&policy, &root, LATEST_ABI).contains(AccessFs::Execute),
            axes.contains(&crate::Axis::ReadExecute),
            "{axes:?} on one path: execute must come from ReadExecute and \
             nothing else"
        );
    }
}

/// The handled set and the rules come from one ABI — the assertion that [`Requested`]'s
/// joining of the two is *live* rather than decorative.
///
/// The rights themselves are pinned literally, at both ends of the range, by
/// [`each_axis_confers_exactly_the_documented_set`](super::grants); pinning `handled` here too
/// would be a third site spelling out the same seventeen rights. This asks only what that one
/// cannot — whether `handled` was read off the same call that produced `rules`.
///
/// The union identity is weak evidence alone, a theorem rather than an observation: read is
/// `from_read` minus `Execute`, write is `from_all` minus `from_read`, execute is the single
/// bit, and landlock's own invariant test asserts `from_read | from_write == from_all`, so the
/// union equals the handled set at *every* ABI. `from_all` is also constant across V5..V8, so
/// `ResolveUnix` arriving in V9 is the only bit two ABIs in the negotiable range can be seen
/// to differ on without a kernel.
///
/// `handled` ⊆ `union` is not a general invariant: it holds here only because the policy
/// saturates every *source* of an fs right — one directory on all three axes, and the
/// unix-socket flag, which since #259 is the only thing conferring `ResolveUnix`. Drop the
/// flag and this fails at `LATEST_ABI`, the three axes no longer partitioning `from_all`.
/// Under default-deny, a handled right no grant reaches is the ordinary case.
///
/// [`Requested`]: super::super::Requested
#[test]
fn the_handled_set_and_the_rules_come_from_one_abi() {
    let dir = tempdir();
    let root = root(&dir);
    let policy = crate::Axis::ALL.into_iter().fold(
        SandboxPolicy::default().allow_unix_sockets(),
        |policy, axis| policy.grant(axis, vetted(&root)),
    );

    for abi in [BASELINE_ABI, LATEST_ABI] {
        let requested = requested_at(&policy, abi);
        let granted = union(&policy, &root, abi);

        // So the agreement below cannot hold by the policy quietly producing fewer grants.
        assert_eq!(
            requested.rules.len(),
            crate::Axis::ALL.len(),
            "{abi:?}: a saturating policy lost a grant"
        );

        // The direction the kernel already refuses: a rule carrying a right outside the
        // handled set is narrowed by `PathBeneath`, which takes the ruleset to
        // `PartiallyEnforced`, declined by `enforcement_verdict`.
        assert!(
            requested.handled.contains(granted),
            "{abi:?}: a rule carries a right the kernel was not told to handle, \
             so the ruleset would come back only partly enforced"
        );
        // The direction nothing refuses: a right the kernel polices that no grant reaches,
        // so some grant confers less than the policy promises.
        assert!(
            granted.contains(requested.handled),
            "{abi:?}: the kernel handles a right no grant confers, so the rules \
             were built at a lower ABI than the handled set"
        );
    }

    let (at_floor, at_ceiling) = (
        requested_at(&policy, BASELINE_ABI).handled,
        requested_at(&policy, LATEST_ABI).handled,
    );

    // The only assertion here that catches a `requested_at` ignoring its `abi`, or both halves
    // pinned to one rung: under either, the agreement above still holds at every ABI.
    assert_ne!(
        at_floor, at_ceiling,
        "the handled set does not move with the ABI, so the parameter is being \
         ignored and the agreement above is vacuous"
    );
    // Named rather than left implicit, so a floor bump past V9 fails *here*, with a
    // reason, instead of turning the inequality above into a tautology.
    assert!(
        at_ceiling.contains(AccessFs::ResolveUnix) && !at_floor.contains(AccessFs::ResolveUnix),
        "ResolveUnix is the one right that differs across the negotiable range, \
         and it no longer does — this test needs a new discriminator"
    );
}

/// The flag, and nothing else, is what puts `ResolveUnix` on a rule — two policies differing
/// only in it, over every axis and both target kinds.
///
/// The half that matters is the *present* half: the mechanism's own failure mode is the bit
/// going missing, so a test that only asserted its absence would pass on a `fs_rules` that
/// never conferred it at all. `ResolveUnix` is spelled out rather than read off
/// `unix_socket_rights`, which would only prove that function agrees with itself.
#[test]
fn the_unix_socket_flag_is_what_confers_resolve_unix() {
    let dir = tempdir();
    let root = root(&dir);
    let file = plain_file(&dir);

    for axis in crate::Axis::ALL {
        for target in [&root, &file] {
            let without = SandboxPolicy::default().grant(axis, vetted(target));
            let with = SandboxPolicy::default()
                .allow_unix_sockets()
                .grant(axis, vetted(target));

            assert!(
                !rule(&without, axis, target).contains(AccessFs::ResolveUnix),
                "{axis:?} on {} dials sockets with the flag unset",
                target.display()
            );
            assert!(
                rule(&with, axis, target).contains(AccessFs::ResolveUnix),
                "{axis:?} on {} cannot dial a socket beneath a path the flag covers",
                target.display()
            );
        }
    }
}

/// The ABI mask, which is the one way to get #259's fix wrong: `PathBeneath` refuses a rule
/// whose rights exceed the handled set outside `CompatLevel`, so conferring `ResolveUnix`
/// unmasked would refuse every run on every kernel shipping today rather than narrow a grant.
///
/// Implicitly covered by [`the_handled_set_and_the_rules_come_from_one_abi`], but as the
/// complaint "the kernel handles a right no grant confers" — which points at the opposite bug.
#[test]
fn the_flag_confers_nothing_below_the_abi_that_has_the_right() {
    let dir = tempdir();
    let root = root(&dir);
    let policy = crate::Axis::ALL.into_iter().fold(
        SandboxPolicy::default().allow_unix_sockets(),
        |policy, axis| policy.grant(axis, vetted(&root)),
    );

    let rights = union(&policy, &root, BASELINE_ABI);

    assert!(
        !rights.contains(AccessFs::ResolveUnix),
        "the floor's rules carry a right the floor cannot handle, so every grant is refused"
    );
    assert!(
        rights.contains(AccessFs::WriteFile),
        "the floor's rules carry nothing, so the assertion above holds for the wrong reason"
    );
}
