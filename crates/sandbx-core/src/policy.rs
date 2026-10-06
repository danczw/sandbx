use std::ffi::OsStr;
use std::path::{Path, PathBuf};

const SYSTEM_EXECUTABLE_PATHS: [&str; 4] = ["/usr", "/bin", "/lib", "/lib64"];

const STANDARD_ENV_NAMES: [&str; 7] = ["PATH", "HOME", "TERM", "LANG", "LC_ALL", "LC_CTYPE", "TZ"];

/// What the resolver hint puts in the child: glibc's stub resolver then opens TCP.
const DNS_OVER_TCP_ENV: [(&str, &str); 1] = [("RES_OPTIONS", "use-vc")];

/// A kind of access a policy can grant on a path.
///
/// With [`Axis::grants`], the only statement of filesystem policy semantics in the
/// workspace: the kernel layer, the guard, the helper argv and the audit record all derive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Axis {
    /// See the path, and nothing more.
    Read,
    /// Change the path, without being able to read it back.
    Write,
    /// See the path *and* run what is in it; the one axis that confers execute.
    ReadExecute,
}

/// What an [`Axis`] confers, in terms no enforcement layer owns.
///
/// Booleans rather than Landlock bits or `FsGuard` buckets, so this module depends neither
/// on the `landlock` crate nor on how a child is invoked. Consumers destructure it, so a
/// right added here fails to compile at each site that maps it.
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

    /// What this axis grants; adding an axis is adding a row here.
    ///
    /// The asymmetry runs one way and nothing but this table enforces it: `ReadExecute`
    /// confers read, a program needing execute on the binary *and* read on the libraries its
    /// loader pulls in; no other grant confers execute, and write confers neither, so a
    /// write-only drop directory stays unreadable. `SECURITY.md` claims this.
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

/// What IP egress a policy grants.
///
/// Not `#[non_exhaustive]`, and nothing matches it with a `_` arm: `HelperArgs::encode`,
/// `net_rules`, `blocked_syscalls` and `AuditEvent::spawned` match exhaustively, so a fourth
/// state is a compile error at every site that would otherwise leave it unenforced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum NetworkPolicy {
    /// No IP egress at all; the command runs in an empty network namespace.
    #[default]
    Denied,
    /// Any TCP port, and UDP and raw sockets with it.
    AnyPort,
    /// TCP connect and bind on these ports only; UDP and raw sockets denied.
    ///
    /// Ports and not destinations: Landlock matches the port alone, so this reaches the
    /// named ports on *every* routable host.
    Ports(Vec<u16>),
}

/// What a sandboxed process is allowed to do.
///
/// Default-deny: construct with [`SandboxPolicy::default`] and widen, so forgetting to
/// configure it yields a useless sandbox rather than an open one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SandboxPolicy {
    readable: Vec<PathBuf>,
    writable: Vec<PathBuf>,
    executable: Vec<PathBuf>,
    network: NetworkPolicy,
    unix_sockets: bool,
    /// Variable *names*, never values; the value is read at spawn time from the harness.
    env: Vec<String>,
    /// A value and not a name, which the other axis forbids: `use-vc` is a compile-time
    /// constant, so argv carrying it would leak nothing.
    dns_over_tcp: bool,
}

impl SandboxPolicy {
    /// Paths the process may read.
    pub fn readable_paths(&self) -> &[PathBuf] {
        self.paths(Axis::Read)
    }

    /// Paths the process may write; writable does not imply readable.
    pub fn writable_paths(&self) -> &[PathBuf] {
        self.paths(Axis::Write)
    }

    /// Paths the process may read *and* execute; no other grant confers execute.
    pub fn executable_paths(&self) -> &[PathBuf] {
        self.paths(Axis::ReadExecute)
    }

    /// Paths granted on `axis`; the named accessors are this with the axis fixed, and a
    /// consumer that must treat every axis alike pairs it with [`Axis::ALL`].
    pub fn paths(&self, axis: Axis) -> &[PathBuf] {
        match axis {
            Axis::Read => &self.readable,
            Axis::Write => &self.writable,
            Axis::ReadExecute => &self.executable,
        }
    }

    /// Every grant this policy holds, as `(axis, path)` pairs, in [`Axis::ALL`] order.
    ///
    /// One pair per grant, not per path: a path granted on two axes appears twice.
    pub fn granted_paths(&self) -> impl Iterator<Item = (Axis, &Path)> {
        Axis::ALL.into_iter().flat_map(move |axis| {
            self.paths(axis)
                .iter()
                .map(move |path| (axis, path.as_path()))
        })
    }

    /// Grant `axis` access to `path`; the one place a path enters a policy.
    #[must_use]
    pub fn grant(mut self, axis: Axis, path: impl AsRef<Path>) -> Self {
        let paths = match axis {
            Axis::Read => &mut self.readable,
            Axis::Write => &mut self.writable,
            Axis::ReadExecute => &mut self.executable,
        };
        paths.push(path.as_ref().to_path_buf());
        self
    }

    /// Whether the process may reach the network *at all*.
    ///
    /// A port allowlist answers yes — `hardening::isolate` reads this to decide whether to
    /// unshare the network namespace, and an allowlist inside an empty netns would permit
    /// nothing. [`network`](Self::network) is how a caller tells narrowed from unrestricted.
    pub fn allows_network(&self) -> bool {
        self.network != NetworkPolicy::Denied
    }

    /// What IP egress the process is granted.
    pub fn network(&self) -> &NetworkPolicy {
        &self.network
    }

    /// Whether the process may open unix-domain sockets.
    ///
    /// Separate from [`allows_network`](Self::allows_network): a socket in the filesystem is
    /// not IP egress, and a network namespace isolates only *abstract* unix sockets.
    pub fn allows_unix_sockets(&self) -> bool {
        self.unix_sockets
    }

    /// Environment variable names the process may inherit; anything unlisted is dropped.
    pub fn allowed_env(&self) -> &[String] {
        &self.env
    }

    /// Variables the policy sets in the child itself, as `(name, value)`.
    ///
    /// Values, where [`allowed_env`](Self::allowed_env) carries names: only compile-time
    /// constants belong here, never anything read from the harness. Applied after the
    /// allowlist, so a variable named both ways gets this value.
    pub fn imposed_env(&self) -> &'static [(&'static str, &'static str)] {
        match self.dns_over_tcp {
            true => &DNS_OVER_TCP_ENV,
            false => &[],
        }
    }

    /// Whether the child may hold a variable called `name`, allowlisted or imposed.
    ///
    /// The one answer `spawn::command` and the helper's inherited-environment check both
    /// use, so what one puts there cannot be what the other refuses.
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

    /// Let the process inherit the variable called `name`.
    ///
    /// An empty name, or one containing `=` or a NUL, is skipped rather than refused, so
    /// nothing `HelperArgs::encode` emits is something `decode` rejects; `sandbx`'s own
    /// `--allow-env` refuses them instead. The value is read from the harness at spawn time,
    /// so a name unset there contributes nothing rather than an empty value.
    #[must_use]
    pub fn allow_env(mut self, name: impl Into<String>) -> Self {
        let name = name.into();
        if !name.is_empty() && !name.contains('=') && !name.contains('\0') {
            self.env.push(name);
        }
        self
    }

    /// Let the process inherit the variables a command needs in order to start.
    ///
    /// With an empty allowlist there is no `PATH`, and a program named without a leading `/`
    /// is looked up in whatever fallback resolves it — `confstr(_CS_PATH)` under glibc's
    /// `execvp`, the shell's wider compiled-in default under a shell — so `cat` starts and
    /// `~/.cargo/bin/x` does not, naming neither cause nor fix. Nothing here conventionally
    /// carries a credential; anything else goes through [`allow_env`](Self::allow_env).
    #[must_use]
    pub fn allow_standard_env(self) -> Self {
        STANDARD_ENV_NAMES
            .iter()
            .copied()
            .fold(self, Self::allow_env)
    }

    /// Grant read access to `path`.
    #[must_use]
    pub fn allow_read(self, path: impl AsRef<Path>) -> Self {
        self.grant(Axis::Read, path)
    }

    /// Grant write access to `path`, and nothing else.
    ///
    /// Neither read nor execute comes with it, so a drop directory granted here cannot be
    /// read back; the `sandbx` CLI grants read alongside write for `--allow-write`.
    #[must_use]
    pub fn allow_write(self, path: impl AsRef<Path>) -> Self {
        self.grant(Axis::Write, path)
    }

    /// Grant read *and* execute access to `path`.
    ///
    /// The only grant that confers execute, and it confers read too (see [`Axis::grants`]).
    /// A directory granted here can run anything that appears in it later.
    #[must_use]
    pub fn allow_read_execute(self, path: impl AsRef<Path>) -> Self {
        self.grant(Axis::ReadExecute, path)
    }

    /// Grant read and execute access to the paths a command needs to start.
    ///
    /// Nothing runs without its loader and shared libraries: with a bare policy even
    /// `/bin/true` dies before `main`. System binaries and libraries only — not `/etc`,
    /// never write. A path absent on this system is skipped, because distributions
    /// disagree about `/lib64` and Landlock rejects a rule for a path that does not exist,
    /// which would turn that disagreement into a failure to sandbox at all.
    #[must_use]
    pub fn allow_system_executables(self) -> Self {
        SYSTEM_EXECUTABLE_PATHS
            .iter()
            .map(Path::new)
            .filter(|path| path.exists())
            .fold(self, Self::allow_read_execute)
    }

    /// Grant IP egress on every port, and only that.
    ///
    /// Unix-domain sockets are a separate grant: a command that can dial
    /// `/run/user/$UID/bus` can ask systemd to start a process outside the sandbox.
    ///
    /// Widens an existing port allowlist to every port.
    #[must_use]
    pub fn allow_network(mut self) -> Self {
        self.network = NetworkPolicy::AnyPort;
        self
    }

    /// Grant TCP connect and bind on `port`, and nothing else on the network.
    ///
    /// Repeat to allowlist several; duplicates collapse, and this cannot narrow
    /// [`allow_network`](Self::allow_network). An allowlist also denies UDP and raw sockets,
    /// and `bind` on every port it does not name — `context/decision-port-allowlist.md`.
    ///
    /// Port 0 is skipped, as [`allow_env`](Self::allow_env) skips a name it cannot encode:
    /// `bind(0)` asks the kernel to choose a port, which an allowlist cannot express.
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

    /// Grant every unix-domain socket the filesystem policy can reach.
    ///
    /// All or nothing: the denial is a seccomp rule on `socket(AF_UNIX, …)`, and seccomp
    /// cannot follow the pointer to `connect`'s path. Per-socket grants need Landlock
    /// ABI V9 (Linux 7.1). The filesystem policy is what bounds which sockets exist to
    /// be dialled.
    #[must_use]
    pub fn allow_unix_sockets(mut self) -> Self {
        self.unix_sockets = true;
        self
    }

    /// Ask glibc's stub resolver to use TCP, by setting `RES_OPTIONS=use-vc` in the child.
    ///
    /// A hint to the resolver inside the command and not a restriction sandbx applies: musl
    /// has no equivalent, and a command ignoring `RES_OPTIONS` is unaffected. Allowlists no
    /// port — TCP 53 still needs [`allow_network_port`](Self::allow_network_port).
    #[must_use]
    pub fn hint_dns_over_tcp(mut self) -> Self {
        self.dns_over_tcp = true;
        self
    }
}
