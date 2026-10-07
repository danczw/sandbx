//! What a grant turns out to open: the path as the kernel spells it, against the path the
//! policy named.
//!
//! No Landlock here — opening a path and reading it back needs no ruleset, so the one half of
//! the seam that can be tested without a capable kernel is tested without one.

use super::{SandboxError, open_grant};

/// A grant named through a symlink, which is the shape the harness never emits and a library
/// caller might.
#[test]
fn a_grant_named_through_a_symlink_is_refused() {
    let work = tempfile::tempdir().expect("a temporary directory");
    let real = work.path().join("real");
    let link = work.path().join("link");
    std::fs::create_dir(&real).expect("a directory to grant");
    std::os::unix::fs::symlink(&real, &link).expect("a symlink to it");

    let error = open_grant(&link).expect_err("a grant that opens as another path");

    assert!(
        matches!(
            &error,
            SandboxError::GrantRedirected { granted, opened }
                if granted == &link && opened == &real
        ),
        "{error} does not name both the grant and what it opened"
    );
}

/// The swap #205 is about, as the helper sees it: the policy carries what the harness
/// resolved, and the link it was resolved through now points somewhere else.
#[test]
fn a_grant_redirected_after_it_was_resolved_is_refused() {
    let work = tempfile::tempdir().expect("a temporary directory");
    let vetted = work.path().join("vetted");
    let elsewhere = work.path().join("elsewhere");
    let link = work.path().join("link");
    std::fs::create_dir(&vetted).expect("the directory the harness vetted");
    std::fs::create_dir(&elsewhere).expect("the directory it is redirected to");
    std::os::unix::fs::symlink(&vetted, &link).expect("a symlink to the vetted one");

    // What the harness would have granted, having resolved the link while it still pointed
    // at `vetted`: a path with no symlink left in it.
    let granted = link.canonicalize().expect("the resolved grant");
    assert_eq!(granted, vetted, "the grant was not resolved to begin with");

    std::fs::remove_dir_all(&vetted).expect("the vetted directory to go");
    std::os::unix::fs::symlink(&elsewhere, &vetted).expect("the swap");

    let error = open_grant(&granted).expect_err("a redirected grant");

    assert!(
        matches!(
            &error,
            SandboxError::GrantRedirected { opened, .. } if opened == &elsewhere
        ),
        "{error} did not report the directory the grant was redirected to"
    );
}

#[test]
fn a_grant_that_opens_as_itself_is_accepted() {
    let work = tempfile::tempdir().expect("a temporary directory");
    let path = work.path().canonicalize().expect("a resolved directory");

    open_grant(&path).expect("a grant naming the directory it opens");
}

/// The rules every run installs, so a host whose `/bin` is a symlink would otherwise refuse
/// every sandbox rather than one grant.
#[test]
fn the_system_grants_every_run_gets_open_as_themselves() {
    for path in crate::SandboxPolicy::default()
        .allow_system_executables()
        .executable_paths()
    {
        open_grant(path).unwrap_or_else(|error| panic!("{error}"));
    }
}

/// A grant naming nothing fails where it failed before the readback existed, so the reason an
/// operator sees for a typo is unchanged.
#[test]
fn a_grant_naming_nothing_still_fails_at_the_open() {
    let error = open_grant(std::path::Path::new("/no/such/granted/path"))
        .expect_err("a grant that cannot be opened at all");

    assert!(
        matches!(error, SandboxError::Landlock { .. }),
        "{error} is not the refusal an unopenable grant has always had"
    );
}
