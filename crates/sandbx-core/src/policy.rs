use std::path::{Path, PathBuf};

const SYSTEM_EXECUTABLE_PATHS: [&str; 4] = ["/usr", "/bin", "/lib", "/lib64"];

const STANDARD_ENV_NAMES: [&str; 7] = ["PATH", "HOME", "TERM", "LANG", "LC_ALL", "LC_CTYPE", "TZ"];

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
/// Three states and no fourth: deliberately not `#[non_exhaustive]`, and nothing may match
/// it with a `_` arm. `HelperArgs::encode`, `ruleset::rights::net_rules`,
/// `seccomp::blocked_syscalls` and `Audit::spawned` each match exhaustively, so a state
/// added here is a compile error at every site that would otherwise leave it unenforced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum NetworkPolicy {
    /// No IP egress at all; the command runs in an empty network namespace.
    #[default]
    Denied,
    /// Any TCP port, and UDP and raw sockets with it.
    AnyPort,
    /// TCP connect and bind on these ports only; UDP and raw sockets denied.
    ///
    /// Ports and not destinations: Landlock's network rules match the port alone, so this
    /// reaches the named ports on *every* routable host. `SECURITY.md` claims no more.
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
    /// A port allowlist answers yes: it is a narrowing of egress, not an absence of it, and
    /// `hardening::isolate` reads this to decide whether to unshare the network namespace.
    /// An allowlist inside an empty netns would allow nothing, so this must not narrow to
    /// mean "unrestricted" — [`network`](Self::network) is how a caller tells the two apart.
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
    /// Widens an existing port allowlist to every port, every grant here only adding reach.
    #[must_use]
    pub fn allow_network(mut self) -> Self {
        self.network = NetworkPolicy::AnyPort;
        self
    }

    /// Grant TCP connect and bind on `port`, and nothing else on the network.
    ///
    /// Repeat to allowlist several; a port already granted is not added twice. UDP and raw
    /// sockets are denied for as long as an allowlist is in force, because a command that
    /// could send arbitrary datagrams would make the allowlist decorative — the cost is
    /// that UDP DNS does not resolve inside the sandbox.
    ///
    /// Port 0 is skipped rather than refused, the way [`allow_env`](Self::allow_env) skips a
    /// name it could not encode: `bind(0)` asks the kernel to pick a port, which an
    /// allowlist cannot express, and a Landlock rule for port 0 matches nothing. `sandbx`'s
    /// own `--allow-network` refuses it loudly instead.
    ///
    /// A no-op once [`allow_network`](Self::allow_network) has granted every port: a builder
    /// only ever adds reach, so narrowing is not something a later call can do.
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
}
