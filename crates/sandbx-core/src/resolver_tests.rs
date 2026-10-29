use super::*;
use std::fs;
use std::os::unix::fs as unix_fs;

/// Names a hosts file must never resolve, in the shape they would arrive in.
const UNLISTED: [&str; 2] = ["www.google.com", "metadata.google.internal"];

/// The addresses a name resolved to, for a body that is about the rendering alone.
fn resolved(name: &str, addresses: &[&str]) -> (String, Vec<IpAddr>) {
    (
        name.to_string(),
        addresses
            .iter()
            .map(|address| address.parse().expect("a test address"))
            .collect(),
    )
}

/// `hosts_body` over owned pairs, `resolved` having nowhere to borrow a name from.
fn body(resolved: &[(String, Vec<IpAddr>)]) -> String {
    let borrowed: Vec<_> = resolved
        .iter()
        .map(|(name, addresses)| (name.as_str(), addresses.clone()))
        .collect();

    hosts_body(&borrowed)
}

#[test]
fn a_resolved_name_gets_a_line_for_every_address_it_has() {
    let rendered = body(&[resolved(
        "example.com",
        &["93.184.216.34", "2606:2800:220::1"],
    )]);

    assert!(
        rendered.contains("93.184.216.34\texample.com\n"),
        "the IPv4 address did not reach the hosts file: {rendered}"
    );
    assert!(
        rendered.contains("2606:2800:220::1\texample.com\n"),
        "the IPv6 address did not reach the hosts file, so a command preferring IPv6 \
         loses the name: {rendered}"
    );
}

#[test]
fn a_name_that_did_not_resolve_contributes_no_line() {
    let rendered = body(&[resolved("nowhere.invalid", &[])]);

    assert!(
        !rendered.contains("nowhere.invalid"),
        "a name with no address was written as one: {rendered}"
    );
}

/// This file is the whole of resolution once `nsswitch.conf` has no `dns` source.
#[test]
fn nothing_the_allowlist_did_not_name_appears_in_the_hosts_file() {
    let rendered = body(&[resolved("example.com", &["93.184.216.34"])]);

    for name in UNLISTED {
        assert!(
            !rendered.contains(name),
            "{name} resolves under a policy that never granted it: {rendered}"
        );
    }
}

#[test]
fn localhost_survives_replacing_the_hosts_file() {
    let rendered = body(&[]);

    assert!(
        rendered.contains("127.0.0.1\tlocalhost\n") && rendered.contains("::1\tlocalhost"),
        "replacing the host's file took localhost with it, and no `dns` source is left \
         to resolve it: {rendered}"
    );
}

/// A host's file in the shape both tests below need: a `hosts` line with `dns` in it, and
/// a `passwd` line reaching somewhere other than `files`.
const HOST_NSSWITCH: &str = "\
# a comment mentioning hosts: and dns
passwd: files systemd
group: files systemd
hosts: files mymachines resolve [!UNAVAIL=return] myhostname dns
networks: files dns
";

/// What makes the bound airtight under glibc rather than dependent on a nameserver being
/// unreachable.
#[test]
fn the_nsswitch_body_leaves_no_dns_source() {
    for host in ["", HOST_NSSWITCH] {
        let rendered = nsswitch_body(host);

        assert!(
            rendered.contains("hosts: files\n") && rendered.contains("networks: files\n"),
            "a database bearing on resolution does not read the files source: {rendered}"
        );

        for line in rendered.lines().filter(|line| !line.starts_with('#')) {
            assert!(
                !matches!(database(line), Some("hosts" | "networks")) || !line.contains("dns"),
                "{line:?} leaves a dns source, so a name the allowlist does not hold still \
                 resolves"
            );
        }
    }
}

/// Only resolution is bounded, or a command on a host looking its users up through
/// `systemd`, `sss` or LDAP cannot resolve its own uid to a name.
#[test]
fn a_database_that_is_not_about_a_name_is_left_as_the_host_had_it() {
    let rendered = nsswitch_body(HOST_NSSWITCH);

    for line in ["passwd: files systemd", "group: files systemd"] {
        assert!(
            rendered.contains(line),
            "{line:?} did not survive, so the command cannot look up a user the host \
             resolves through a source other than files: {rendered}"
        );
    }
}

#[test]
fn the_resolver_body_names_no_nameserver() {
    for line in RESOLV_BODY.lines().filter(|line| !line.starts_with('#')) {
        assert!(
            !line.contains("nameserver"),
            "{line:?} names a nameserver for musl to ask"
        );
    }
}

/// A libc parser takes `#` as a comment and splits fields on whitespace, so a name
/// carrying either would forge a line — which the rendering leaves to `allow_dns` to skip.
#[test]
fn a_name_that_could_forge_a_line_never_reaches_the_rendering() {
    for name in [
        "example.com\t127.0.0.1 evil.test",
        "example.com evil.test",
        "example.com\n127.0.0.1 evil.test",
        "# 127.0.0.1 evil.test",
        "",
    ] {
        let policy = crate::SandboxPolicy::default().allow_dns(name);

        assert!(
            policy.allowed_dns_names().is_empty(),
            "{name:?} entered a policy, and the hosts file is rendered from these"
        );
    }
}

#[test]
fn a_policy_that_bounds_nothing_renders_nothing() {
    assert!(
        files(&crate::SandboxPolicy::default()).is_none(),
        "a run with no name allowlist was given files to mount over /etc"
    );
}

/// Getting `nsswitch.conf`'s side of this wrong leaves glibc's built-in `hosts: files
/// dns` in place.
#[test]
fn only_the_file_musl_can_do_without_is_optional() {
    let policy = crate::SandboxPolicy::default().allow_dns("localhost");
    let rendered = files(&policy)
        .expect("a bounded policy renders its files")
        .files;

    for file in rendered {
        assert_eq!(
            file.required,
            file.target != Path::new(RESOLV_CONF),
            "{} is the wrong side of the refusal: skipping a missing hosts file or \
             nsswitch.conf leaves resolution unbounded",
            file.target.display()
        );
    }
}

#[test]
fn every_rendered_file_is_one_the_policy_grants_read_on() {
    let policy = crate::SandboxPolicy::default().allow_dns("localhost");
    let rendered = files(&policy)
        .expect("a bounded policy renders its files")
        .files;

    for file in rendered {
        assert!(
            RESOLVER_FILES.contains(&file.target.to_str().expect("an ASCII path")),
            "{} is mounted but not in RESOLVER_FILES, so nothing grants read on it",
            file.target.display()
        );
    }
}

/// `mount(2)` resolves the target, so the bind lands on what the link points at — and that
/// is the name a grant on the link is pinned to.
#[test]
fn a_symlinked_entry_is_bound_under_the_name_the_bind_lands_on() {
    let dir = tempfile::tempdir().expect("a directory to link within");
    let target = dir.path().join("stub-resolv.conf");
    let link = dir.path().join("resolv.conf");
    fs::write(&target, "options attempts:1\n").expect("a file to link to");
    unix_fs::symlink(&target, &link).expect("a link to the file");

    // Resolved, as every caller's path arrives: a grant carries what `vet` canonicalized.
    let target = target.canonicalize().expect("the link's target to resolve");
    let bound = [link.as_path()];

    assert!(
        bound_by_any(&bound, &target),
        "the name the bind lands on was not reported, so a grant there is pinned to the \
         host's file and the run refuses as a substituted object"
    );
    assert!(
        bound_by_any(&bound, &link),
        "the entry's own spelling was not reported"
    );
    assert!(
        !bound_by_any(&bound, dir.path()),
        "the directory holding a bound file was reported, and a bind leaves its inode alone"
    );
}
