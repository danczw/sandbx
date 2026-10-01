use std::path::{Path, PathBuf};

/// Where a system keeps the binaries and libraries a command needs to start.
const SYSTEM_EXECUTABLE_PATHS: [&str; 4] = ["/usr", "/bin", "/lib", "/lib64"];

/// A kind of access a policy can grant on a path.
///
/// The axis *names* a grant; [`Axis::grants`] says what it confers. Those two
/// together are the only statement of filesystem policy semantics in the
/// workspace: the kernel layer, the in-process guard, the helper argv and the
/// audit record all derive from them rather than restating them. Two layers
/// restating the same semantics by hand is what produced #49 and #50, where one
/// enforced what the other refused.
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
/// Three booleans rather than Landlock bits or `FsGuard` buckets, because the
/// two layers have to agree and neither one's vocabulary can express the other.
/// Each layer maps these onto its own: `helper.rs` into `BitFlags<AccessFs>`,
/// `fs_guard.rs` into its readable/writable roots.
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
    /// A `const` array rather than an iterator trait: consumers loop over it to
    /// derive their own tables, and two of them — the audit record's
    /// fixed-arity destructuring, and `Axis::ALL.map(..)` — need the length at
    /// compile time, which is what makes a forgotten axis a build failure there
    /// rather than a silently missing grant.
    pub const ALL: [Axis; 3] = [Axis::Read, Axis::Write, Axis::ReadExecute];

    /// What this axis grants. **The table.**
    ///
    /// Adding an axis is adding a row here; the compiler then names every site
    /// that cannot derive its answer from one.
    ///
    /// The asymmetry is deliberate and runs one way: `ReadExecute` confers read,
    /// because a program needs execute on the binary *and* read on the libraries
    /// its loader pulls in, so an execute-only grant would start nothing. No
    /// grant confers execute, and write confers neither — a write-only drop
    /// directory stays unreadable. `SECURITY.md` claims exactly this.
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
/// Default-deny: a policy grants nothing until something is explicitly added.
/// Construct with [`SandboxPolicy::default`] and widen from there, so forgetting
/// to configure it yields a useless sandbox rather than an open one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SandboxPolicy {
    readable: Vec<PathBuf>,
    writable: Vec<PathBuf>,
    executable: Vec<PathBuf>,
    network: bool,
    unix_sockets: bool,
}

impl SandboxPolicy {
    /// Paths the process may read.
    pub fn readable_paths(&self) -> &[PathBuf] {
        self.paths(Axis::Read)
    }

    /// Paths the process may write.
    ///
    /// Writable does not imply readable — the two are granted separately, so a
    /// write-only drop directory stays unreadable.
    pub fn writable_paths(&self) -> &[PathBuf] {
        self.paths(Axis::Write)
    }

    /// Paths the process may read *and* execute.
    ///
    /// Separate from [`readable_paths`] because execute is a distinct capability
    /// that no other grant confers: reading a file and running it are different
    /// powers, and only this axis carries the second.
    ///
    /// [`readable_paths`]: Self::readable_paths
    pub fn executable_paths(&self) -> &[PathBuf] {
        self.paths(Axis::ReadExecute)
    }

    /// Paths granted on `axis`.
    ///
    /// The named accessors above are this with the axis fixed. A consumer that
    /// has to treat every axis alike — the helper argv, the Landlock rules, the
    /// audit counts — goes through [`Axis::ALL`] and this, so adding an axis
    /// does not mean finding every such loop by hand.
    pub fn paths(&self, axis: Axis) -> &[PathBuf] {
        match axis {
            Axis::Read => &self.readable,
            Axis::Write => &self.writable,
            Axis::ReadExecute => &self.executable,
        }
    }

    /// Every grant this policy holds, as `(axis, path)` pairs.
    ///
    /// In [`Axis::ALL`] order, and one pair per grant rather than per path: a
    /// path granted on two axes appears twice, because the two grants are
    /// different permissions and a consumer that collapsed them would be
    /// enforcing neither.
    pub fn granted_paths(&self) -> impl Iterator<Item = (Axis, &Path)> {
        Axis::ALL.into_iter().flat_map(move |axis| {
            self.paths(axis)
                .iter()
                .map(move |path| (axis, path.as_path()))
        })
    }

    /// Grant `axis` access to `path`.
    ///
    /// The one place a path enters a policy; the named `allow_*` methods are
    /// this with the axis fixed, and they are where the documentation of what
    /// each one means lives.
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
    /// Separate from [`allows_network`] because reaching a host daemon over a
    /// socket in the filesystem is not IP egress, and a network namespace does
    /// not contain it — it isolates only *abstract* unix sockets.
    ///
    /// [`allows_network`]: Self::allows_network
    pub fn allows_unix_sockets(&self) -> bool {
        self.unix_sockets
    }

    /// Grant read access to `path`.
    #[must_use]
    pub fn allow_read(self, path: impl AsRef<Path>) -> Self {
        self.grant(Axis::Read, path)
    }

    /// Grant write access to `path`, and nothing else.
    ///
    /// Write alone: neither read nor execute comes with it, so a drop directory
    /// granted here cannot be read back. The `sandbx` CLI deliberately grants
    /// read alongside write for `--allow-write`, because that trap is rarely
    /// what a person at a terminal wants — but the narrow form is what this
    /// method gives, and it is what a library caller composes from.
    #[must_use]
    pub fn allow_write(self, path: impl AsRef<Path>) -> Self {
        self.grant(Axis::Write, path)
    }

    /// Grant read *and* execute access to `path`.
    ///
    /// The only grant that confers execute. Named for both rights because it
    /// hands out both: running a program needs `Execute` on the binary and
    /// `ReadFile` on the libraries its loader pulls in, so an execute-only grant
    /// would not actually let anything start.
    ///
    /// Prefer [`allow_read`] wherever the process only needs to *see* the files.
    /// A directory granted here can run anything that appears in it later.
    ///
    /// [`allow_read`]: Self::allow_read
    #[must_use]
    pub fn allow_read_execute(self, path: impl AsRef<Path>) -> Self {
        self.grant(Axis::ReadExecute, path)
    }

    /// Grant read and execute access to the paths a command needs to start.
    ///
    /// Nothing runs without its loader and shared libraries: with a bare policy
    /// even `/bin/true` dies before `main`, and the failure surfaces as a
    /// permission error on `exec` rather than anything naming the cause. Every
    /// caller that spawns a process needs this, so it is one grant here instead
    /// of the same four paths copied per caller.
    ///
    /// Read and execute, and deliberately narrow: system binaries and libraries,
    /// not `/etc`, and never write access. Being able to run `ls` should not
    /// imply being able to replace it.
    ///
    /// Paths absent on this system are skipped — distributions disagree about
    /// `/lib64`, and Landlock rejects a rule for a path that does not exist,
    /// which would turn that disagreement into a failure to sandbox at all.
    #[must_use]
    pub fn allow_system_executables(self) -> Self {
        SYSTEM_EXECUTABLE_PATHS
            .iter()
            .map(Path::new)
            .filter(|path| path.exists())
            .fold(self, Self::allow_read_execute)
    }

    /// Grant network access.
    ///
    /// IP egress only. Unix-domain sockets are a separate grant, because a
    /// command that can dial `/run/user/$UID/bus` can ask systemd to start a
    /// process outside the sandbox entirely — which is not what "let it reach
    /// the network" is understood to mean.
    #[must_use]
    pub fn allow_network(mut self) -> Self {
        self.network = true;
        self
    }

    /// Grant unix-domain sockets.
    ///
    /// **All of them**, not a chosen one. The denial is a seccomp rule on
    /// `socket(AF_UNIX, …)`, and seccomp compares register values: the path
    /// passed to `connect` lives behind a pointer it cannot follow. Landlock
    /// gained a path-scoped right for this in ABI V9 (Linux 6.15), and a
    /// per-socket grant can be added once that is available in practice.
    ///
    /// So this opens every pathname socket the filesystem policy can reach —
    /// an ssh-agent, a docker socket, the session bus. Grant it deliberately,
    /// and keep the filesystem policy narrow, because that is what still bounds
    /// which sockets exist to be dialled.
    #[must_use]
    pub fn allow_unix_sockets(mut self) -> Self {
        self.unix_sockets = true;
        self
    }
}
