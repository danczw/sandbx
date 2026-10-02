use std::path::{Path, PathBuf};

/// Where a system keeps the binaries and libraries a command needs to start.
const SYSTEM_EXECUTABLE_PATHS: [&str; 4] = ["/usr", "/bin", "/lib", "/lib64"];

/// The environment variables a command conventionally needs in order to start.
const STANDARD_ENV_NAMES: [&str; 7] = ["PATH", "HOME", "TERM", "LANG", "LC_ALL", "LC_CTYPE", "TZ"];

/// A kind of access a policy can grant on a path.
///
/// The axis names a grant and [`Axis::grants`] says what it confers; together they are
/// the only statement of filesystem policy semantics in the workspace. The kernel
/// layer, the in-process guard, the helper argv and the audit record all derive from
/// them rather than restating them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Axis {
    /// See the path, and nothing more.
    Read,
    /// Change the path, without being able to read it back.
    Write,
    /// See the path *and* run what is in it. The one axis that confers execute.
    ReadExecute,
}

/// What an [`Axis`] confers, in terms no enforcement layer owns.
///
/// Booleans rather than Landlock bits or `FsGuard` buckets, so this module depends
/// neither on the `landlock` crate nor on how a child is invoked. Every consumer
/// destructures it rather than reading its fields, so a right added here fails to
/// compile at each site that has to map it.
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
    ///
    /// What makes a forgotten axis a build failure is not this array but the exhaustive
    /// `match` each site unable to derive its answer pairs with the loop.
    pub const ALL: [Axis; 3] = [Axis::Read, Axis::Write, Axis::ReadExecute];

    /// What this axis grants; adding an axis is adding a row here.
    ///
    /// The asymmetry runs one way. `ReadExecute` confers read, because a program needs
    /// execute on the binary *and* read on the libraries its loader pulls in. No grant
    /// confers execute, and write confers neither — a write-only drop directory stays
    /// unreadable. `SECURITY.md` claims exactly this.
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

/// What a sandboxed process is allowed to do.
///
/// Default-deny: construct with [`SandboxPolicy::default`] and widen, so forgetting to
/// configure it yields a useless sandbox rather than an open one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SandboxPolicy {
    readable: Vec<PathBuf>,
    writable: Vec<PathBuf>,
    executable: Vec<PathBuf>,
    network: bool,
    unix_sockets: bool,
    /// Variable *names*, never values: the value is read from the harness's own
    /// environment when the command is spawned.
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

    /// Paths granted on `axis`.
    ///
    /// The named accessors are this with the axis fixed. A consumer that has to treat
    /// every axis alike goes through [`Axis::ALL`] and this, so adding an axis does not
    /// mean finding every such loop by hand.
    pub fn paths(&self, axis: Axis) -> &[PathBuf] {
        match axis {
            Axis::Read => &self.readable,
            Axis::Write => &self.writable,
            Axis::ReadExecute => &self.executable,
        }
    }

    /// Every grant this policy holds, as `(axis, path)` pairs, in [`Axis::ALL`] order.
    ///
    /// One pair per grant, not per path: a path granted on two axes appears twice,
    /// because a consumer that collapsed them would enforce neither.
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

    /// Whether the process may reach the network.
    pub fn allows_network(&self) -> bool {
        self.network
    }

    /// Whether the process may open unix-domain sockets.
    ///
    /// Separate from [`allows_network`](Self::allows_network): a socket in the
    /// filesystem is not IP egress, and a network namespace isolates only *abstract*
    /// unix sockets.
    pub fn allows_unix_sockets(&self) -> bool {
        self.unix_sockets
    }

    /// Environment variable names the process may inherit; anything unlisted is dropped
    /// before the command starts.
    pub fn allowed_env(&self) -> &[String] {
        &self.env
    }

    /// Let the process inherit the variable called `name`.
    ///
    /// The value is read from the harness's own environment at spawn time, so a name
    /// unset there contributes nothing rather than an empty value. An empty name, or one
    /// containing `=` or a NUL, is skipped rather than refused later, so nothing
    /// `HelperArgs::encode` emits is something `decode` rejects; `sandbx`'s own
    /// `--allow-env` refuses them instead, because a person at a terminal needs telling.
    /// Names are not deduplicated, matching the path grants.
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
    /// With an empty allowlist there is no `PATH`, and a program named without a leading
    /// `/` is looked up in whatever fallback resolves it — `confstr(_CS_PATH)` under
    /// glibc's `execvp`, the shell's wider compiled-in default under a shell — so `cat`
    /// starts and `~/.cargo/bin/x` does not, naming neither cause nor fix. Narrow by
    /// design: nothing here conventionally carries a credential, and anything else is
    /// named through [`allow_env`](Self::allow_env). The default stays empty because a
    /// caller passing absolute program paths needs none of it.
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
    /// Neither read nor execute comes with it, so a drop directory granted here cannot
    /// be read back. The `sandbx` CLI grants read alongside write for `--allow-write`;
    /// this narrow form is what a library caller composes from.
    #[must_use]
    pub fn allow_write(self, path: impl AsRef<Path>) -> Self {
        self.grant(Axis::Write, path)
    }

    /// Grant read *and* execute access to `path`.
    ///
    /// The only grant that confers execute, and it confers read too because running a
    /// program needs `Execute` on the binary and `ReadFile` on the libraries its loader
    /// pulls in. A directory granted here can run anything that appears in it later, so
    /// prefer [`allow_read`](Self::allow_read) where the process only needs to see.
    #[must_use]
    pub fn allow_read_execute(self, path: impl AsRef<Path>) -> Self {
        self.grant(Axis::ReadExecute, path)
    }

    /// Grant read and execute access to the paths a command needs to start.
    ///
    /// Nothing runs without its loader and shared libraries: with a bare policy even
    /// `/bin/true` dies before `main`, as a permission error on `exec` naming no cause.
    /// System binaries and libraries only — not `/etc`, never write. Paths absent on
    /// this system are skipped, because distributions disagree about `/lib64` and
    /// Landlock rejects a rule for a path that does not exist, which would turn that
    /// disagreement into a failure to sandbox at all.
    #[must_use]
    pub fn allow_system_executables(self) -> Self {
        SYSTEM_EXECUTABLE_PATHS
            .iter()
            .map(Path::new)
            .filter(|path| path.exists())
            .fold(self, Self::allow_read_execute)
    }

    /// Grant IP egress, and only that.
    ///
    /// Unix-domain sockets are a separate grant: a command that can dial
    /// `/run/user/$UID/bus` can ask systemd to start a process outside the sandbox.
    #[must_use]
    pub fn allow_network(mut self) -> Self {
        self.network = true;
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
