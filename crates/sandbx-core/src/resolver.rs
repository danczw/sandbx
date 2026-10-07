//! What a bounded resolver is on disk: the three files it replaces, and what goes in them.
//!
//! Rendering is pure, so every body is assertable without a namespace or a nameserver. The
//! lookups run in the helper, before any filter is installed, which is the only place they can
//! run at all: the harness would have to carry the addresses across the argv the command reads.
//! `helper::resolver` installs what this renders, and `context/decision-egress-proxy.md` is why
//! resolution is bounded by a hosts file rather than by the DNS responder that note first
//! specified.

use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;

/// The allowlist itself, and the only one of the three whose body varies per run.
const HOSTS: &str = "/etc/hosts";

/// What removes glibc's `dns` source, leaving [`HOSTS`] as the whole of resolution.
const NSSWITCH: &str = "/etc/nsswitch.conf";

/// For musl, which ignores [`NSSWITCH`] entirely.
const RESOLV_CONF: &str = "/etc/resolv.conf";

/// Every path a policy that bounds resolution replaces with one of sandbx's own.
///
/// Public because such a policy also grants read on exactly these — `ruleset::rights` derives
/// those rules from this list — and because a reader of `SECURITY.md` is owed the list of files
/// the command no longer sees the host's copy of.
pub const RESOLVER_FILES: [&str; 3] = [HOSTS, NSSWITCH, RESOLV_CONF];

/// Lines every libc expects to find whatever else a hosts file holds.
///
/// Replacing the host's file would otherwise take `localhost` with it, and with no `dns`
/// source left there is nothing to resolve it by.
const LOOPBACK: &str = "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n";

/// `hosts: files` is the load-bearing line: a database absent from this file falls back to
/// glibc's built-in default, which for `hosts` and `networks` *includes* `dns`.
const NSSWITCH_BODY: &str = "\
# sandbx: `files` throughout and no `dns` source, so /etc/hosts is the whole of resolution.
hosts: files
networks: files
passwd: files
group: files
shadow: files
";

/// No `nameserver` line, and the bound does not rest on that alone — see the body.
const RESOLV_BODY: &str = "\
# sandbx: no nameserver. glibc has no `dns` source to use one (see /etc/nsswitch.conf); musl
# ignores nsswitch.conf and falls back to 127.0.0.1:53, which a port allowlist denies at the
# socket, UDP included.
options attempts:1 timeout:1
";

/// One file to be bind-mounted over its `/etc` counterpart.
pub(crate) struct File {
    /// The `/etc` path the command will see this at.
    pub(crate) target: &'static Path,
    /// What it will hold.
    pub(crate) body: String,
    /// Whether an absent target refuses the run rather than skipping the mount.
    ///
    /// Bind-mounting needs the target to already exist, and this is the difference between a
    /// host that cannot be bounded and one that needs no bounding there.
    pub(crate) required: bool,
}

/// Resolve the policy's names and render the files that bound resolution to them.
///
/// `None` when the policy bounds nothing, which is what keeps a run with no `--allow-dns` off
/// the mount path entirely rather than mounting the host's own contents back over itself.
pub(crate) fn files(policy: &crate::SandboxPolicy) -> Option<[File; 3]> {
    if !policy.bounds_resolution() {
        return None;
    }

    let resolved: Vec<_> = policy
        .allowed_dns_names()
        .iter()
        .map(|name| (name.as_str(), addresses(name)))
        .collect();

    Some([
        File {
            target: Path::new(HOSTS),
            body: hosts_body(&resolved),
            // A hosts file is the whole mechanism, so a host with none can bound nothing.
            required: true,
        },
        File {
            target: Path::new(NSSWITCH),
            body: NSSWITCH_BODY.to_string(),
            // Absent, glibc uses `hosts: files dns`, so skipping this would leave the `dns`
            // source alive and the bound empty.
            required: true,
        },
        File {
            target: Path::new(RESOLV_CONF),
            body: RESOLV_BODY.to_string(),
            // Absent, musl falls back to 127.0.0.1:53 — which is what this file leaves it
            // with anyway, so there is nothing to refuse over.
            required: false,
        },
    ])
}

/// Every address `name` resolves to right now, in the order the resolver returned them.
///
/// `getaddrinfo` through [`ToSocketAddrs`], so a name resolves exactly as it would for the
/// command — no DNS client of our own, and nothing of `/etc/resolv.conf` reimplemented. Port 0
/// because only the address is wanted; `SOCK_STREAM` is what collapses the per-protocol
/// duplicates the raw call returns.
///
/// Empty for a name that does not resolve, which contributes no line rather than failing the
/// run, as an absent path contributes no Landlock rule. A lookup that hangs is bounded by the
/// run's own `timeout` and by nothing here.
fn addresses(name: &str) -> Vec<IpAddr> {
    let mut found = Vec::new();

    if let Ok(resolved) = (name, 0u16).to_socket_addrs() {
        for address in resolved.map(|socket| socket.ip()) {
            if !found.contains(&address) {
                found.push(address);
            }
        }
    }

    found
}

/// A hosts file holding `resolved` and the loopback lines, and nothing else.
///
/// One line per address, both families, so a name with an A and a AAAA record resolves to both
/// — a command that prefers IPv6 would otherwise lose the name rather than fall back.
///
/// Takes what each name resolved to rather than resolving itself, so what the file says is
/// assertable without a nameserver.
fn hosts_body(resolved: &[(&str, Vec<IpAddr>)]) -> String {
    use std::fmt::Write as _;

    let mut body = String::from(
        "# sandbx: the names --allow-dns granted, and nothing else resolves at all.\n",
    );
    body.push_str(LOOPBACK);

    for (name, addresses) in resolved {
        for address in addresses {
            let _ = writeln!(body, "{address}\t{name}");
        }
    }

    body
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Nothing but the allowlist and loopback may be resolvable, this file being the whole of
    /// resolution once `nsswitch.conf` has no `dns` source.
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

    /// The one line that makes the bound airtight under glibc rather than dependent on a
    /// nameserver being unreachable.
    #[test]
    fn the_nsswitch_body_leaves_no_dns_source() {
        assert!(
            NSSWITCH_BODY.contains("hosts: files\n"),
            "the hosts database does not read the files source: {NSSWITCH_BODY}"
        );

        for line in NSSWITCH_BODY.lines().filter(|line| !line.starts_with('#')) {
            assert!(
                !line.contains("dns"),
                "{line:?} leaves a dns source, so a name the allowlist does not hold still \
                 resolves"
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

    /// Every rendered body is read by a libc parser that takes `#` as a comment and splits
    /// fields on whitespace, so a name carrying either would forge a line. `allow_dns` skips
    /// such a name and `HelperArgs::decode` refuses it; this is the assertion that the
    /// rendering depends on that.
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

    /// `required` is what decides whether an absent target refuses the run, and getting
    /// `nsswitch.conf` wrong would leave glibc's built-in `hosts: files dns` in place.
    #[test]
    fn only_the_file_musl_can_do_without_is_optional() {
        let policy = crate::SandboxPolicy::default().allow_dns("localhost");
        let rendered = files(&policy).expect("a bounded policy renders its files");

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
        let rendered = files(&policy).expect("a bounded policy renders its files");

        for file in rendered {
            assert!(
                RESOLVER_FILES.contains(&file.target.to_str().expect("an ASCII path")),
                "{} is mounted but not in RESOLVER_FILES, so nothing grants read on it",
                file.target.display()
            );
        }
    }
}
