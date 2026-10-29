use super::super::root::owned_paths;
use super::super::root::tests::{env, reaches};
use super::Grants;
use crate::PolicyError;
use sandbx_core::{Axis, VettedPath};
use std::env;
use std::os::unix::fs as unix_fs;
use std::path::{Path, PathBuf};

fn bare() -> Grants {
    Grants {
        allow_read: Vec::new(),
        allow_write: Vec::new(),
        allow_exec: Vec::new(),
        allow_network: None,
        allow_unix_sockets: false,
        allow_env: Vec::new(),
        dns_over_tcp: false,
        allow_dns: Vec::new(),
    }
}

/// The paths of a set of grants. The object beside each is derived from the path, so these
/// tests assert over the spelling and the pin follows (#212).
fn spellings(granted: &[VettedPath]) -> Vec<&Path> {
    granted.iter().map(VettedPath::path).collect()
}

#[test]
fn a_path_flag_suppresses_the_default() {
    for axis in Axis::ALL {
        let mut grants = bare();
        // Matched, not pushed into one field, so a new path flag fails to compile here
        // too rather than quietly keeping the default.
        match axis {
            Axis::Read => grants.allow_read.push(PathBuf::from("/srv")),
            Axis::Write => grants.allow_write.push(PathBuf::from("/srv")),
            Axis::ReadExecute => grants.allow_exec.push(PathBuf::from("/srv")),
        }

        assert!(
            grants.paths_given(),
            "{axis:?} left the working-directory default in place"
        );
    }
}

/// Driven off `Axis::ALL`, so a new path flag joins the refusal instead of being the one
/// spelling that still reaches a key.
#[test]
fn every_path_axis_refuses_an_owned_root() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let home = directory.path();
    let owned = owned_paths(&env(&[(
        "HOME",
        home.to_str().expect("a UTF-8 temporary path"),
    )]));

    for axis in Axis::ALL {
        let mut grants = bare();
        match axis {
            Axis::Read => grants.allow_read.push(home.to_path_buf()),
            Axis::Write => grants.allow_write.push(home.to_path_buf()),
            Axis::ReadExecute => grants.allow_exec.push(home.to_path_buf()),
        }

        assert!(
            reaches(&grants.paths(axis)[0], &owned),
            "{axis:?} reached no owned path"
        );
    }
}

/// A grant is pinned to the object at its path, and a path naming nothing has none — so
/// this refuses in the harness where Landlock used to refuse it in the helper (#212).
#[test]
fn a_grant_naming_nothing_cannot_be_pinned() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let mut grants = bare();
    grants.allow_read.push(directory.path().join("no-such-dir"));

    let error = grants.policy().expect_err("a grant naming nothing");

    assert!(
        matches!(error, PolicyError::UnpinnableGrant { .. }),
        "{error} is not the unpinnable-grant refusal"
    );
    assert!(
        error.to_string().contains("a path that exists"),
        "{error} does not say what to name instead"
    );
}

/// The helper opens what the policy carries, from a process whose working directory is
/// not this one's — so a grant left relative would be a different directory there (#205).
#[test]
fn a_relative_grant_reaches_the_policy_absolute() {
    let mut grants = bare();
    grants.allow_read.push(PathBuf::from("src"));

    let policy = grants.policy().expect("the flags describe a policy");
    let expected = env::current_dir()
        .expect("a readable working directory")
        .join("src")
        .canonicalize()
        .expect("the crate this test is in has a src directory");

    assert_eq!(
        spellings(policy.readable_paths()),
        [expected.as_path()],
        "a relative grant crossed the seam relative"
    );
}

/// The other half: vetted through the link and granted through it too, the helper would
/// open whatever it points at by then.
#[test]
fn a_grant_through_a_symlink_reaches_the_policy_resolved() {
    let work = tempfile::tempdir().expect("a temporary directory");
    let real = work.path().canonicalize().expect("a resolved directory");
    let link = work.path().join("link");
    unix_fs::symlink(&real, &link).expect("a symlink to it");

    let mut grants = bare();
    grants.allow_write.push(link);

    let policy = grants.policy().expect("the flags describe a policy");

    assert_eq!(
        spellings(policy.writable_paths()),
        [real.as_path()],
        "a symlinked grant crossed the seam unresolved"
    );
    assert_eq!(
        spellings(policy.readable_paths()),
        [real.as_path()],
        "the read a write flag confers was granted in another form than the write"
    );
}

/// Suppressing here would silently narrow a policy whose path axes were never touched.
#[test]
fn a_non_path_flag_leaves_the_default_alone() {
    let mut grants = bare();
    grants.allow_network = Some(vec![443]);
    grants.allow_unix_sockets = true;
    grants.allow_env.push("TERM".to_string());
    grants.dns_over_tcp = true;

    assert!(
        !grants.paths_given(),
        "a flag naming no path suppressed the default"
    );
}
