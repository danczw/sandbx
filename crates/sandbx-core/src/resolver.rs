//! What a bounded resolver is on disk: the three files it replaces, and what goes in them.
//! Rendering is pure, so every body is assertable without a namespace or a nameserver. The
//! lookups run in the helper, the only place they can: the harness would have to carry the
//! addresses across the argv the command reads. `helper::resolver` installs what this
//! renders; `context/decision-port-allowlist.md` is why a hosts file and not a DNS responder.

use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;

/// The allowlist itself, and the only one of the three whose body varies per run.
const HOSTS: &str = "/etc/hosts";

/// What removes glibc's `dns` source, leaving [`HOSTS`] as the whole of resolution.
const NSSWITCH: &str = "/etc/nsswitch.conf";

/// For musl, which ignores [`NSSWITCH`] entirely.
const RESOLV_CONF: &str = "/etc/resolv.conf";

/// Every path a policy that bounds resolution replaces with one of sandbx's own. Public
/// because such a policy also grants read on exactly these — `ruleset::rights` derives
/// those rules from this list.
pub const RESOLVER_FILES: [&str; 3] = [HOSTS, NSSWITCH, RESOLV_CONF];

/// Whether `path` names one of [`RESOLVER_FILES`] as the bind will land on it. Each entry
/// is matched by its own name and by what it resolves to, because `mount(2)` resolves its
/// target and a pin does not: a systemd `/etc/resolv.conf` is a symlink, so the bind
/// replaces the stub it points at, which is the name a grant on it is pinned to. An entry
/// resolving to nothing matches by name alone. Never of `path` itself: resolving it here would
/// judge a spelling no caller vetted. [`SandboxPolicy::grant_bound_by_resolver`] passes a path
/// already resolved; `sandbx-cli`'s wrapper of this function passes both spellings on purpose,
/// the typed one matching where an entry cannot be canonicalized at all. An entry retargeted
/// between this and the bind fails closed — the pair is kept, and the pin refuses the run
/// in the helper.
///
/// [`SandboxPolicy::grant_bound_by_resolver`]: crate::SandboxPolicy::grant_bound_by_resolver
pub fn bound_by_resolver(path: &Path) -> bool {
    bound_by_any(&RESOLVER_FILES.map(Path::new), path)
}

/// [`bound_by_resolver`] over an arbitrary list: on a host whose own three files are regular,
/// resolving changes nothing and the branch that matters cannot be reached from the real one.
fn bound_by_any(bound: &[&Path], path: &Path) -> bool {
    bound
        .iter()
        .any(|bound| *bound == path || bound.canonicalize().is_ok_and(|real| real == path))
}

/// Lines every libc expects whatever else a hosts file holds: with no `dns` source left, there
/// is nothing else to resolve `localhost` by.
const LOOPBACK: &str = "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n";

/// The two databases that bear on resolution, set to the only source left. Written in
/// whether the host's file named them or not: a database absent from `nsswitch.conf`
/// falls back to glibc's built-in default, which for these two *includes* `dns`.
const BOUNDED_SOURCES: &str = "\
# sandbx: `hosts` and `networks` read files alone, so /etc/hosts is the whole of resolution.
hosts: files
networks: files
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
    /// Whether an absent target refuses the run rather than skipping the mount — a bind
    /// needing its target to exist already.
    pub(crate) required: bool,
}

/// What a bounded policy resolved to, and how much of it did not resolve.
pub(crate) struct Resolved {
    /// The three files to be bind-mounted over their `/etc` counterparts.
    pub(crate) files: [File; 3],

    /// How many allowlisted names resolved to no address at all; carried out, not reported
    /// here, since this runs in the re-exec'd helper. A count, not the names —
    /// `guide-logging.md` keeps values off the trail.
    pub(crate) unresolved: usize,
}

/// Resolve the policy's names and render the files that bound resolution to them. `None`
/// when the policy bounds nothing, which keeps a run with no `--allow-dns` off the mount
/// path entirely.
pub(crate) fn files(policy: &crate::SandboxPolicy) -> Option<Resolved> {
    if !policy.bounds_resolution() {
        return None;
    }

    let resolved: Vec<_> = policy
        .allowed_dns_names()
        .iter()
        .map(|name| (name.as_str(), addresses(name)))
        .collect();

    let unresolved = resolved
        .iter()
        .filter(|(_, addresses)| addresses.is_empty())
        .count();

    let files = [
        File {
            target: Path::new(HOSTS),
            body: hosts_body(&resolved),
            // A hosts file is the whole mechanism, so a host with none can bound nothing.
            required: true,
        },
        File {
            target: Path::new(NSSWITCH),
            body: nsswitch_body(&std::fs::read_to_string(NSSWITCH).unwrap_or_default()),
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
    ];

    Some(Resolved { files, unresolved })
}

/// Every address `name` resolves to right now, in the order the resolver returned them.
/// `getaddrinfo` through [`ToSocketAddrs`], so a name resolves exactly as it would for the
/// command, with no DNS client of our own, and port 0 since only the address is wanted.
/// Empty for a name that does not resolve, contributing no line rather than failing the
/// run, as an absent path contributes no Landlock rule — a lookup that hangs is bounded by
/// the run's own `timeout` and by nothing here. A link-local IPv6 address is dropped:
/// `ip()` discards the `scope_id` that makes one routable, a hosts file has no column to
/// carry it back, and `connect` to a scopeless `fe80::/10` address is `EINVAL`.
fn addresses(name: &str) -> Vec<IpAddr> {
    let mut found = Vec::new();

    if let Ok(resolved) = (name, 0u16).to_socket_addrs() {
        for address in resolved.map(|socket| socket.ip()) {
            let scoped = match address {
                IpAddr::V6(v6) => v6.is_unicast_link_local(),
                IpAddr::V4(_) => false,
            };

            if !scoped && !found.contains(&address) {
                found.push(address);
            }
        }
    }

    found
}

/// The host's `nsswitch.conf` with `hosts` and `networks` rewritten and every other line
/// kept. Line by line rather than a file of sandbx's own: `passwd` and `group` reach
/// `systemd`, `sss` or LDAP on an ordinary host, and writing `files` over those would leave
/// a command whose own account lives there unable to look its user up. Only `hosts` and
/// `networks` bear on a name; `BOUNDED_SOURCES` alone covers an empty `host`, as for an
/// unreadable file.
fn nsswitch_body(host: &str) -> String {
    let mut body = String::from(BOUNDED_SOURCES);

    for line in host.lines() {
        if !matches!(database(line), Some("hosts" | "networks")) {
            body.push_str(line);
            body.push('\n');
        }
    }

    body
}

/// The database an `nsswitch.conf` line configures: the name before its first colon, as glibc
/// reads it. `None` for a comment, and for a line configuring nothing.
fn database(line: &str) -> Option<&str> {
    let name = line.split_once(':')?.0.trim();

    (!name.is_empty() && !name.starts_with('#')).then_some(name)
}

/// A hosts file holding `resolved` and the loopback lines, and nothing else. One line per
/// address, both families, so a name with an A and a AAAA record resolves to both — a
/// command that prefers IPv6 would otherwise lose the name rather than fall back.
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
#[path = "resolver_tests.rs"]
mod tests;
