//! What a grant turns out to open: the path as the kernel spells it and the object behind it,
//! against the path the policy named and the object it was vetted as.
//!
//! No Landlock here — opening a path, reading it back and stat'ing it need no ruleset, so the
//! one half of the seam that can be tested without a capable kernel is tested without one.

use std::os::fd::{AsFd as _, AsRawFd as _};
use std::path::Path;

use super::{SandboxError, open_grant};
use crate::helper::ruleset::rights::RuleTarget;
use crate::{ObjectId, VettedPath};

/// A grant as `HelperArgs::decode` would build it: the path verbatim off argv, pinned to
/// whatever object the third token named. Nothing here resolves, which is how a spelling
/// [`VettedPath::vet`] could never produce reaches [`open_grant`].
fn off_the_wire(path: impl AsRef<Path>, pin: &Path) -> VettedPath {
    let object = VettedPath::vet(pin)
        .expect("a path to pin the grant to")
        .object();

    VettedPath::from_wire(path.as_ref(), object)
}

/// A resolver file as `rights::fs_rules` names one: no pin, and `&'static` because
/// `RESOLVER_FILES` are literals. Leaked, the fixtures being temporary.
fn installed(path: impl AsRef<Path>) -> RuleTarget<'static> {
    RuleTarget::Installed(Box::leak(path.as_ref().to_path_buf().into_boxed_path()))
}

/// A grant named through a symlink, which is the shape the harness never emits and argv can
/// still carry.
#[test]
fn a_grant_named_through_a_symlink_is_refused() {
    let work = tempfile::tempdir().expect("a temporary directory");
    let real = work.path().join("real");
    let link = work.path().join("link");
    std::fs::create_dir(&real).expect("a directory to grant");
    std::os::unix::fs::symlink(&real, &link).expect("a symlink to it");

    let granted = off_the_wire(&link, &real);
    let error =
        open_grant(&RuleTarget::Granted(&granted)).expect_err("a grant that opens as another path");

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

    // What the harness would have granted, having vetted the link while it still pointed at
    // `vetted`: a path with no symlink left in it.
    let granted = VettedPath::vet(&link).expect("the vetted grant");
    assert_eq!(
        granted.path(),
        vetted,
        "the grant was not resolved to begin with"
    );

    std::fs::remove_dir_all(&vetted).expect("the vetted directory to go");
    std::os::unix::fs::symlink(&elsewhere, &vetted).expect("the swap");

    let error = open_grant(&RuleTarget::Granted(&granted)).expect_err("a redirected grant");

    assert!(
        matches!(
            &error,
            SandboxError::GrantRedirected { opened, .. } if opened == &elsewhere
        ),
        "{error} did not report the directory the grant was redirected to"
    );
}

/// The swap #212 is about: one real directory renamed over another, leaving no symlink and no
/// change of spelling, so only the object tells the two apart.
#[test]
fn a_grant_renamed_over_after_it_was_vetted_is_refused() {
    let work = tempfile::tempdir().expect("a temporary directory");
    let granted_at = work.path().join("granted");
    let substitute = work.path().join("substitute");
    std::fs::create_dir(&granted_at).expect("the directory the harness vetted");
    std::fs::create_dir(&substitute).expect("the directory put in its place");

    let granted = VettedPath::vet(&granted_at).expect("the vetted grant");

    std::fs::remove_dir(&granted_at).expect("the vetted directory to go");
    std::fs::rename(&substitute, &granted_at).expect("the swap");

    let error =
        open_grant(&RuleTarget::Granted(&granted)).expect_err("a grant whose object was replaced");

    assert!(
        matches!(
            &error,
            SandboxError::GrantReplaced { granted: named, vetted, opened }
                if named == &granted_at && vetted != opened
        ),
        "{error} did not report the grant as a substituted object"
    );

    // Not vacuous: the readback cannot see this one, so the spelling has to be unchanged.
    let fd = landlock::PathFd::new(&granted_at).expect("the substitute, opened");
    let link = format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd());
    assert_eq!(
        std::fs::read_link(link).expect("the path it reads back as"),
        granted_at,
        "the substitution changed the spelling, so the readback would have caught it"
    );
}

#[test]
fn a_grant_that_opens_as_itself_is_accepted() {
    let work = tempfile::tempdir().expect("a temporary directory");
    let granted = VettedPath::vet(work.path()).expect("the vetted grant");

    open_grant(&RuleTarget::Granted(&granted))
        .expect("a grant naming the directory and object it opens");
}

/// The pin is the whole difference between the two targets, on one fixture: the object under
/// the name is not the one it was vetted as, which refuses as a grant and passes as a resolver
/// file — the bind `helper::resolver` just made *is* a substituted object, and the only answer
/// to compare it against would be this process's own.
#[test]
fn an_installed_path_is_not_pinned_to_the_object_under_it() {
    let work = tempfile::tempdir().expect("a temporary directory");
    let named = work.path().join("resolv.conf");
    let substitute = work.path().join("substitute");
    std::fs::write(&named, b"nameserver 203.0.113.1\n").expect("the file the harness saw");
    std::fs::write(&substitute, b"nameserver 203.0.113.2\n").expect("the file put in its place");

    let granted = VettedPath::vet(&named).expect("the vetted grant");
    std::fs::rename(&substitute, &named).expect("the swap");

    assert!(
        matches!(
            open_grant(&RuleTarget::Granted(&granted)),
            Err(SandboxError::GrantReplaced { .. })
        ),
        "the grant arm stopped measuring the pin, so this fixture proves nothing"
    );
    open_grant(&installed(&named)).expect("a resolver file, which carries no pin to disagree");
}

/// The readback is not the pin and does not travel with it: a rule on an inode sandbx did not
/// place is refused whichever target names it.
#[test]
fn an_installed_path_redirected_is_still_refused() {
    let work = tempfile::tempdir().expect("a temporary directory");
    let real = work.path().join("real.conf");
    let link = work.path().join("link.conf");
    std::fs::write(&real, b"nameserver 203.0.113.1\n").expect("a file to point at");
    std::os::unix::fs::symlink(&real, &link).expect("a symlink to it");

    let error = open_grant(&installed(&link)).expect_err("a resolver path opening as another");

    assert!(
        matches!(
            &error,
            SandboxError::GrantRedirected { granted, opened }
                if granted == &link && opened == &real
        ),
        "{error} does not name both the installed path and what it opened"
    );
}

/// The rules every run installs, so a host whose `/bin` is a symlink would otherwise refuse
/// every sandbox rather than one grant.
#[test]
fn the_system_grants_every_run_gets_open_as_themselves() {
    for path in crate::SandboxPolicy::default()
        .allow_system_executables()
        .executable_paths()
    {
        open_grant(&RuleTarget::Granted(path)).unwrap_or_else(|error| panic!("{error}"));
    }
}

/// A grant naming nothing fails where it failed before either check existed, so the reason an
/// operator sees for a typo is unchanged.
#[test]
fn a_grant_naming_nothing_still_fails_at_the_open() {
    let granted = VettedPath::from_wire(
        "/no/such/granted/path",
        ObjectId::parse("259:17").expect("a device and an inode"),
    );

    let error = open_grant(&RuleTarget::Granted(&granted))
        .expect_err("a grant that cannot be opened at all");

    assert!(
        matches!(error, SandboxError::Landlock { .. }),
        "{error} is not the refusal an unopenable grant has always had"
    );
}
