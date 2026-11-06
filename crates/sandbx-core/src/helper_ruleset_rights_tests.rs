use super::opens_as_itself;
use std::fs;
use std::os::unix::fs as unix_fs;

/// The branch that decides whether a resolver path gets a rule at all. `resolver_paths`
/// reads the host's `/etc`, so on a host whose `resolv.conf` is a plain file nothing else
/// runs the symlink arm — the arm that refused every run on a systemd-resolved host.
#[test]
fn a_symlink_never_opens_as_itself() {
    let scratch = tempfile::tempdir().expect("a temporary directory");
    let real = scratch.path().join("real.conf");
    let link = scratch.path().join("link.conf");
    fs::write(&real, b"nameserver 203.0.113.1\n").expect("a file to point at");
    unix_fs::symlink(&real, &link).expect("a symlink to it");

    assert!(
        opens_as_itself(&real),
        "a plain file does not open as itself, so a bounded run installs no rule at all"
    );
    assert!(
        !opens_as_itself(&link),
        "a rule would be installed for a symlink, whose bind landed on the target — so \
         `open_grant`'s readback disagrees with the spelling and refuses the run"
    );
    assert!(
        !opens_as_itself(&scratch.path().join("absent.conf")),
        "an absent path would get a rule Landlock cannot open"
    );
}

/// A dangling link is still a link: skipped at the bind, it must be skipped here too.
#[test]
fn a_dangling_symlink_is_skipped_like_an_absent_path() {
    let scratch = tempfile::tempdir().expect("a temporary directory");
    let link = scratch.path().join("dangling.conf");
    unix_fs::symlink(scratch.path().join("nothing"), &link).expect("a dead link");

    assert!(
        !opens_as_itself(&link),
        "a dangling link got a rule, so a target appearing before stage 2 would be granted \
         without a bind over it"
    );
}
