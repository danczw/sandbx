//! What a run is allowed to reach: the axes, the network and env policy, and the
//! builders that widen them.
//!
//! Over the 400-line budget on purpose: each axis is an accessor and a builder that
//! have to agree, so a new axis is one edit in one file rather than two.

use std::ffi::OsStr;
use std::path::Path;

mod vetted;

pub(crate) use vetted::Confirmation;
pub use vetted::{ObjectId, VettedPath};

const SYSTEM_EXECUTABLE_PATHS: [&str; 4] = ["/usr", "/bin", "/lib", "/lib64"];

const STANDARD_ENV_NAMES: [&str; 7] = ["PATH", "HOME", "TERM", "LANG", "LC_ALL", "LC_CTYPE", "TZ"];

/// What the resolver hint puts in the child: glibc's stub resolver then opens TCP.
const DNS_OVER_TCP_ENV: [(&str, &str); 1] = [("RES_OPTIONS", "use-vc")];

/// The first of `paths` that is a directory now; a grant naming nothing is not one.
fn first_directory(paths: &[VettedPath]) -> Option<&Path> {
    paths
        .iter()
        .map(VettedPath::path)
        .find(|path| path.is_dir())
}

/// A kind of access a policy can grant on a path; [`Axis::grants`] is the one
/// statement of what each kind means. See `context/decision-axis-table.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Axis {
    /// See the path, and nothing more.
    Read,
    /// Change the path, without being able to read it back.
    Write,
    /// See the path and run what is in it; the one axis that confers execute.
    ReadExecute,
}

/// What an [`Axis`] confers, in terms no enforcement layer owns: booleans, not
/// Landlock bits, so a right added here fails to compile at every mapping site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grants {
    /// May see the path's contents.
    pub read: bool,
    /// May change the path. Does not imply `read`.
    pub write: bool,
    /// May execute what the path contains.
    pub execute: bool,
}

impl Axis {
    /// Every axis, in the order a policy and the helper argv carry them.
    pub const ALL: [Axis; 3] = [Axis::Read, Axis::Write, Axis::ReadExecute];

    /// What this axis grants; adding an axis is adding a row here. The asymmetry
    /// `SECURITY.md` claims: `ReadExecute` alone confers execute (and read, for a loader's
    /// libraries); write confers neither, so a write-only drop directory stays unreadable.
    pub const fn grants(self) -> Grants {
        let (read, write, execute) = match self {
            Self::Read => (true, false, false),
            Self::Write => (false, true, false),
            Self::ReadExecute => (true, false, true),
        };

        Grants {
            read,
            write,
            execute,
        }
    }
}

/// What IP egress a policy grants. Not `#[non_exhaustive]`, so a fourth state is a
/// compile error at every site that would otherwise leave it unenforced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum NetworkPolicy {
    /// No IP egress at all; the command runs in an empty network namespace.
    #[default]
    Denied,
    /// Any TCP port, and UDP and raw sockets with it.
    AnyPort,
    /// TCP connect and bind on these ports only; UDP and raw sockets denied. Landlock
    /// matches the port, not the destination, so this reaches the named ports on every
    /// routable host.
    Ports(Vec<u16>),
}

/// What a sandboxed process is allowed to do. Default-deny: construct with
/// [`SandboxPolicy::default`] and widen, so an unconfigured policy is useless, not open.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SandboxPolicy {
    readable: Vec<VettedPath>,
    writable: Vec<VettedPath>,
    executable: Vec<VettedPath>,
    network: NetworkPolicy,
    unix_sockets: bool,
    /// Variable names, never values; the value is read at spawn time from the harness.
    env: Vec<String>,
    /// Implies a value, unlike `env`, and only because that value is a compile-time constant.
    dns_over_tcp: bool,
    /// Host names, never addresses: the addresses are resolved in the helper, per run.
    dns_names: Vec<String>,
}

impl SandboxPolicy {
    /// Paths the process may read.
    pub fn readable_paths(&self) -> &[VettedPath] {
        self.paths(Axis::Read)
    }

    /// Paths the process may write; writable does not imply readable.
    pub fn writable_paths(&self) -> &[VettedPath] {
        self.paths(Axis::Write)
    }

    /// Paths the process may read and execute; no other grant confers execute.
    pub fn executable_paths(&self) -> &[VettedPath] {
        self.paths(Axis::ReadExecute)
    }

    /// Paths granted on `axis`; pair with [`Axis::ALL`] to treat every axis alike.
    pub fn paths(&self, axis: Axis) -> &[VettedPath] {
        match axis {
            Axis::Read => &self.readable,
            Axis::Write => &self.writable,
            Axis::ReadExecute => &self.executable,
        }
    }

    /// Every grant this policy holds, as `(axis, path)` pairs, in [`Axis::ALL`] order:
    /// one pair per grant, not per path, so a path granted on two axes appears twice.
    pub fn granted_paths(&self) -> impl Iterator<Item = (Axis, &VettedPath)> {
        Axis::ALL
            .into_iter()
            .flat_map(move |axis| self.paths(axis).iter().map(move |path| (axis, path)))
    }

    /// A grant naming a file this policy's own resolver will bind over, or `None` if none
    /// does. The pin cannot hold here: the harness vets the host's file, `helper::resolver` binds
    /// sandbx's own over it, and `open_grant` would measure the grant against an object sandbx
    /// itself replaced — refused rather than waived in the substituting process itself (see
    /// `context/decision-grant-identity.md`). An exact name, not a prefix — which names
    /// count is [`bound_by_resolver`]'s — since the pin is on the granted path's own inode,
    /// so a bind over a file inside `/etc` leaves `/etc` alone and `--allow-read /etc`
    /// collides with nothing. `HelperArgs::decode` does not re-run this check — it stays
    /// I/O-free, and this reads the filesystem — so it lives on the policy, reaching an
    /// embedder's argv spawn too.
    ///
    /// [`bound_by_resolver`]: crate::bound_by_resolver
    pub fn grant_bound_by_resolver(&self) -> Option<&Path> {
        if !self.bounds_resolution() {
            return None;
        }

        self.granted_paths()
            .map(|(_, granted)| granted.path())
            .find(|path| crate::bound_by_resolver(path))
    }

    /// Where a command run under this policy starts, or `None` if it grants nowhere to be. The
    /// first writable directory, else the first readable one, not the first entry of
    /// [`granted_paths`](Self::granted_paths): that order puts `Read` ahead of `Write` and
    /// `ReadExecute` last, which would start a writable run read-only, or one granted only
    /// execute inside the system binaries. A directory and not merely a path, because
    /// `chdir` to a file (e.g. `--allow-write /dev/null`) fails the spawn.
    pub fn working_root(&self) -> Option<&Path> {
        first_directory(&self.writable).or_else(|| first_directory(&self.readable))
    }

    /// Grant `axis` access to `path`; the one place a path enters a policy. Takes a
    /// [`VettedPath`], not a bare path, so the grant carries the object the harness measured
    /// and the helper decodes with no unpinned grant to judge. No I/O happens here, because
    /// the helper decodes a policy through this too: it refuses a grant whose name now opens
    /// as something else ([`GrantRedirected`]) or whose object is no longer the vetted one
    /// ([`GrantReplaced`]).
    ///
    /// [`GrantRedirected`]: crate::SandboxError::GrantRedirected
    /// [`GrantReplaced`]: crate::SandboxError::GrantReplaced
    #[must_use]
    pub fn grant(mut self, axis: Axis, path: VettedPath) -> Self {
        let paths = match axis {
            Axis::Read => &mut self.readable,
            Axis::Write => &mut self.writable,
            Axis::ReadExecute => &mut self.executable,
        };
        paths.push(path);
        self
    }

    /// Whether the process may reach the network at all; a port allowlist answers yes.
    /// `hardening::isolate` unshares the network namespace unless this is true, since an
    /// allowlist inside an empty netns would permit nothing.
    pub fn allows_network(&self) -> bool {
        self.network != NetworkPolicy::Denied
    }

    /// What IP egress the process is granted.
    pub fn network(&self) -> &NetworkPolicy {
        &self.network
    }

    /// Whether the process may open unix-domain sockets, separate from
    /// [`allows_network`](Self::allows_network): a network namespace isolates only
    /// abstract unix sockets, not pathname ones in the filesystem.
    pub fn allows_unix_sockets(&self) -> bool {
        self.unix_sockets
    }

    /// Environment variable names the process may inherit; anything unlisted is dropped.
    pub fn allowed_env(&self) -> &[String] {
        &self.env
    }

    /// Variables the policy sets in the child itself, as `(name, value)`; only compile-time
    /// constants belong here. Applied after the allowlist, so a name carried both ways
    /// arrives with this value.
    pub fn imposed_env(&self) -> &'static [(&'static str, &'static str)] {
        match self.dns_over_tcp {
            true => &DNS_OVER_TCP_ENV,
            false => &[],
        }
    }

    /// Whether the child may hold a variable called `name`, allowlisted or imposed: the one
    /// answer `spawn::command` and the helper's inherited-environment check share.
    pub fn permits_env(&self, name: &OsStr) -> bool {
        self.env.iter().any(|allowed| name == OsStr::new(allowed))
            || self
                .imposed_env()
                .iter()
                .any(|(imposed, _)| name == OsStr::new(imposed))
    }

    /// Whether the policy asks the child's resolver to use TCP.
    pub fn hints_dns_over_tcp(&self) -> bool {
        self.dns_over_tcp
    }

    /// Host names the process may resolve; empty leaves resolution exactly as the host has it.
    pub fn allowed_dns_names(&self) -> &[String] {
        &self.dns_names
    }

    /// Whether resolution is bounded at all, which is what costs the command a mount namespace:
    /// the one answer `hardening::isolate` and `ruleset::rights` share, so the namespace the
    /// first unshares cannot differ from the files the second grants read on.
    pub fn bounds_resolution(&self) -> bool {
        !self.dns_names.is_empty()
    }

    /// Why this policy's name allowlist would bound nothing, or `None` if it bounds what it
    /// says. The one combination that reports as applied and holds nothing: the files are
    /// bound, `Spawned` records `dns_names`, and the command asks a resolver that answers for
    /// every name. Lives on the policy, not the CLI alone, so [`SandboxedCommand`] and
    /// `HelperArgs::decode` both reach it. `Grants::policy` refuses four shapes of this; a
    /// name allowlist with no egress is the fifth, pointless rather than unenforceable, so
    /// it is reported here instead.
    ///
    /// [`SandboxedCommand`]: crate::SandboxedCommand
    pub fn unbounded_resolution(&self) -> Option<&'static str> {
        if !self.bounds_resolution() {
            return None;
        }

        if self.dns_over_tcp {
            return Some(
                "a name allowlist asks no nameserver and `--dns-over-tcp` asks one for every \
                 name",
            );
        }

        // glibc asks nscd over `/var/run/nscd/socket` before it reads `nsswitch.conf`, on a
        // path only `__nss_configure_lookup` turns off — so the rendered file cannot.
        if self.unix_sockets {
            return Some("a local resolver answers over a pathname socket, asked before nsswitch");
        }

        match &self.network {
            NetworkPolicy::AnyPort => {
                Some("every port is allowlisted, so the command reaches a nameserver by IP literal")
            }
            NetworkPolicy::Ports(ports) if ports.contains(&NAMESERVER_PORT) => {
                Some("port 53 is allowlisted, so a nameserver answers for every name")
            }
            NetworkPolicy::Ports(_) | NetworkPolicy::Denied => None,
        }
    }

    /// Let the process inherit the variable called `name`. An empty name, or one containing
    /// `=` or a NUL, is skipped rather than refused, so nothing `HelperArgs::encode` emits
    /// is something `decode` rejects — `sandbx`'s `--allow-env` refuses them instead.
    #[must_use]
    pub fn allow_env(mut self, name: impl Into<String>) -> Self {
        let name = name.into();
        if !name.is_empty() && !name.contains('=') && !name.contains('\0') {
            self.env.push(name);
        }
        self
    }

    /// Let the process inherit the variables a command needs in order to start. With no
    /// `PATH`, glibc's `execvp` falls back to `confstr(_CS_PATH)`, so `cat` starts
    /// and `~/.cargo/bin/x` does not — a shell falls back to its own wider default instead
    /// (see `context/decision-environment-allowlist.md`). Nothing here carries a
    /// credential; anything else needs [`allow_env`](Self::allow_env).
    #[must_use]
    pub fn allow_standard_env(self) -> Self {
        STANDARD_ENV_NAMES
            .iter()
            .copied()
            .fold(self, Self::allow_env)
    }

    /// Grant read access to `path`.
    #[must_use]
    pub fn allow_read(self, path: VettedPath) -> Self {
        self.grant(Axis::Read, path)
    }

    /// Grant write access to `path`, and nothing else — a drop directory granted here cannot
    /// be read back. The `sandbx` CLI's `--allow-write` grants read alongside it.
    #[must_use]
    pub fn allow_write(self, path: VettedPath) -> Self {
        self.grant(Axis::Write, path)
    }

    /// Grant read and execute access to `path`; the only grant that confers execute (and
    /// read too, see [`Axis::grants`]). A directory granted here can run anything that
    /// appears in it later.
    #[must_use]
    pub fn allow_read_execute(self, path: VettedPath) -> Self {
        self.grant(Axis::ReadExecute, path)
    }

    /// Grant read and execute access to the paths a command needs to start: without its
    /// loader and shared libraries, even `/bin/true` dies before `main`. Each path is skipped
    /// if absent rather than granted, since Landlock rejects a rule for a path that does not
    /// exist — a host without `/lib64` would otherwise fail to sandbox at all.
    /// [`vet`](VettedPath::vet) resolves first, which a merged-`/usr` host needs — it spells
    /// `/bin` as a symlink to `/usr/bin`, and a grant has to name what it opens. Pinned here
    /// rather than left to the caller: this is the
    /// one grant set reached without vetting a path, and an unpinned arm would reopen the
    /// case [`grant`](Self::grant) was built to not have.
    #[must_use]
    pub fn allow_system_executables(self) -> Self {
        SYSTEM_EXECUTABLE_PATHS
            .iter()
            .filter_map(|path| VettedPath::vet(path).ok())
            .fold(self, Self::allow_read_execute)
    }

    /// Grant IP egress on every port, and only that; widens an existing port allowlist.
    /// Unix-domain sockets stay a separate grant — a command that can dial
    /// `/run/user/$UID/bus` can ask systemd to start a process outside the sandbox.
    #[must_use]
    pub fn allow_network(mut self) -> Self {
        self.network = NetworkPolicy::AnyPort;
        self
    }

    /// Grant TCP connect and bind on `port`, and nothing else on the network. Repeat to
    /// allowlist several; duplicates collapse, and this cannot narrow
    /// [`allow_network`](Self::allow_network). Also denies UDP, raw sockets, and `bind` on
    /// every other port (`context/decision-port-allowlist.md`). Port 0 is skipped: `bind(0)`
    /// asks the kernel to choose, which cannot be allowlisted.
    #[must_use]
    pub fn allow_network_port(mut self, port: u16) -> Self {
        if port == 0 {
            return self;
        }

        self.network = match self.network {
            NetworkPolicy::Denied => NetworkPolicy::Ports(vec![port]),
            NetworkPolicy::AnyPort => NetworkPolicy::AnyPort,
            NetworkPolicy::Ports(mut ports) => {
                if !ports.contains(&port) {
                    ports.push(port);
                }
                NetworkPolicy::Ports(ports)
            }
        };
        self
    }

    /// Grant unix-domain sockets, every one the command can reach.
    ///
    /// All or nothing: seccomp denies `socket(AF_UNIX, …)` and a connectionless `socketpair`,
    /// and cannot follow the pointer to `connect`'s path. The path mechanism is Landlock's
    /// `ResolveUnix` (ABI V9, Linux 7.1), which this confers on the paths it granted; below
    /// V9 nothing bounds which socket is dialled.
    #[must_use]
    pub fn allow_unix_sockets(mut self) -> Self {
        self.unix_sockets = true;
        self
    }

    /// Ask glibc's stub resolver to use TCP, by setting `RES_OPTIONS=use-vc` in the child. A
    /// hint, not a restriction: musl has no equivalent, and a command ignoring `RES_OPTIONS`
    /// is unaffected. Allowlists no port — TCP 53 still needs
    /// [`allow_network_port`](Self::allow_network_port).
    #[must_use]
    pub fn hint_dns_over_tcp(mut self) -> Self {
        self.dns_over_tcp = true;
        self
    }

    /// Let `name` resolve, bounding resolution to the names granted this way; repeat for
    /// several, duplicates collapsing. The first call imposes the bound: the helper renders a
    /// hosts file holding only these names, with no nameserver, so an ungranted name stops
    /// resolving (resolution, not connection — `context/decision-egress-proxy.md`). A name
    /// that is empty, over [`DNS_NAME_LIMIT`] bytes, or carries a NUL, whitespace or `#` is
    /// skipped rather than refused, as in [`allow_env`](Self::allow_env); the last three
    /// would forge a field or a comment in the rendered hosts file.
    #[must_use]
    pub fn allow_dns(mut self, name: impl Into<String>) -> Self {
        let name = name.into();
        if is_resolvable_name(&name) && !self.dns_names.contains(&name) {
            self.dns_names.push(name);
        }
        self
    }
}

/// The longest name [`SandboxPolicy::allow_dns`] will carry, from DNS's own 253-byte limit on
/// a presentation-form name. Bounded at all because the argv carrying the names has
/// `MAX_ARG_STRLEN` to fit under.
pub const DNS_NAME_LIMIT: usize = 253;

/// The port a nameserver answers on, which a bounded policy may not allowlist.
pub const NAMESERVER_PORT: u16 = 53;

/// Whether `name` is one the helper can both carry and render; shared with
/// `HelperArgs::decode`, which refuses what this rejects, so a name arriving on the
/// wire skipped by `encode` did not come from it.
pub(crate) fn is_resolvable_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= DNS_NAME_LIMIT
        && !name.contains('#')
        && !name.contains('\0')
        && !name.chars().any(char::is_whitespace)
}
