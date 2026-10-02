//! The mapping itself: one rule per grant, each narrowed to its target, and what
//! the kernel ends up enforcing once overlapping grants are unioned.
//!
//! Asked through [`requested_at`] rather than `fs_rules` directly, because that is
//! what `apply` installs — the wrapper is where a dropped grant or a re-fused
//! narrowing would now hide, so the coverage belongs on it and not on the
//! function it calls (#87).

use super::{AccessFs, BASELINE_ABI, LATEST_ABI, SandboxPolicy, requested_at};

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
    let matches: Vec<_> = requested_at(policy, LATEST_ABI)
        .rules
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
fn union(
    policy: &SandboxPolicy,
    path: &std::path::Path,
    abi: landlock::ABI,
) -> landlock::BitFlags<AccessFs> {
    requested_at(policy, abi)
        .rules
        .into_iter()
        .filter(|(_, candidate, _)| *candidate == path)
        .fold(landlock::BitFlags::EMPTY, |union, (_, _, rights)| {
            union | rights
        })
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
    assert!(
        requested_at(&SandboxPolicy::default(), LATEST_ABI)
            .rules
            .is_empty()
    );
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

    assert_eq!(requested_at(&policy, LATEST_ABI).rules.len(), 3);
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
            union(&policy, dir.path(), LATEST_ABI).contains(AccessFs::Execute),
            axes.contains(&crate::Axis::ReadExecute),
            "{axes:?} on one path: execute must come from ReadExecute and \
             nothing else"
        );
    }
}

/// The handled set and the rules come from one ABI.
///
/// `apply` used to build these two from separate expressions — `from_all(abi)` for
/// what the kernel is told to police, `fs_rules(policy, abi)` for the rules — with
/// only a comment saying the ABI had to be the same in both. [`Requested`] now
/// returns them together, and this is the assertion that the joining is *live*
/// rather than decorative (#87).
///
/// **What this test is not.** The rights themselves are pinned, literally and at
/// both ends of the range, by
/// [`each_axis_confers_exactly_the_documented_set`](super::grants). That is
/// stronger coverage of the mapping than anything here, and pinning `handled`
/// literally would make a third site spelling out the same sixteen-or-seventeen
/// rights — against that test's own argument for one place to edit. So this asks
/// only the question that one cannot: whether `handled` was read off the same call
/// that produced `rules`.
///
/// **Why the union identity is weak evidence on its own.** It is a theorem, not an
/// observation: read is `from_read` minus `Execute`, write is `from_all` minus
/// `from_read`, execute is the single bit, and landlock's own invariant test
/// asserts `from_read | from_write == from_all`. So the union equals the handled
/// set at *every* ABI, as an algebraic consequence. Worse, `from_all` is constant
/// across V5..V8 — V6, V7 and V8 add no `AccessFs` right at all — so `ResolveUnix`
/// arriving in V9 is the single bit anywhere in the negotiable range that a
/// kernel-free test could notice two ABIs differing on. The four assertions below
/// are therefore deliberate about which one carries which weight.
///
/// **`handled` ⊆ `union` is not a general invariant.** It holds here only because
/// the policy is deliberately saturating — one directory on all three axes.
/// Default-deny means a handled right that no grant reaches is the ordinary,
/// correct case, and the kernel policing a right nobody was granted is exactly
/// what a sandbox is. Do not generalise this to an arbitrary policy.
///
/// [`Requested`]: super::super::Requested
#[test]
fn the_handled_set_and_the_rules_come_from_one_abi() {
    let dir = tempdir();
    let policy = crate::Axis::ALL
        .into_iter()
        .fold(SandboxPolicy::default(), |policy, axis| {
            policy.grant(axis, dir.path())
        });

    for abi in [BASELINE_ABI, LATEST_ABI] {
        let requested = requested_at(&policy, abi);
        let granted = union(&policy, dir.path(), abi);

        // So the agreement below cannot hold by the policy having quietly
        // produced fewer grants than it names.
        assert_eq!(
            requested.rules.len(),
            crate::Axis::ALL.len(),
            "{abi:?}: a saturating policy lost a grant"
        );

        // The direction the kernel already refuses: a rule carrying a right
        // outside the handled set is narrowed by `PathBeneath`, which takes the
        // ruleset to `PartiallyEnforced`, and `enforcement_verdict` declines that.
        assert!(
            requested.handled.contains(granted),
            "{abi:?}: a rule carries a right the kernel was not told to handle, \
             so the ruleset would come back only partly enforced"
        );
        // The direction nothing refuses: a right the kernel is told to police
        // that no grant can reach, which is a grant conferring less than the
        // policy promises.
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

    // The only assertion here that catches a `requested_at` ignoring its `abi`,
    // or both halves pinned to one rung: under either, the agreement above still
    // holds at every ABI.
    assert_ne!(
        at_floor, at_ceiling,
        "the handled set does not move with the ABI, so the parameter is being \
         ignored and the agreement above is vacuous"
    );
    // Named rather than left implicit, so that a floor bump past V9 fails *here*
    // — with a reason — instead of quietly turning the inequality above into a
    // tautology that passes under every mutation.
    assert!(
        at_ceiling.contains(AccessFs::ResolveUnix) && !at_floor.contains(AccessFs::ResolveUnix),
        "ResolveUnix is the one right that differs across the negotiable range, \
         and it no longer does — this test needs a new discriminator"
    );
}
