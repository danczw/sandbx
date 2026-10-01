//! Unit tests for the ruleset layer: [`grants`] for what an axis confers,
//! [`rules`] for the one-rule-per-grant mapping, [`compat`] for the ABI ladder
//! and the enforcement verdict.
//!
//! All of them are deliberately kernel-free — no root, no network namespace, no
//! Landlock-capable host (#52) — so they run anywhere. `tests/enforcement.rs` is
//! where the live kernel is involved.

mod compat;
mod grants;
mod rules;

use crate::SandboxPolicy;
use landlock::AccessFs;

use super::compat::{LATEST_ABI, NEGOTIABLE_ABI, enforcement_verdict};
use super::rights::{fs_rules, rights_for};

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
