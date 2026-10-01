//! The mapping itself: one rule per grant, each narrowed to its target, and what
//! the kernel ends up enforcing once overlapping grants are unioned.

use super::{AccessFs, LATEST_ABI, SandboxPolicy, fs_rules, plain_file, rule, tempdir, union};

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
