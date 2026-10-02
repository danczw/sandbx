use std::path::{Path, PathBuf};

/// Where a system keeps the binaries and libraries a command needs to start.
const SYSTEM_EXECUTABLE_PATHS: [&str; 4] = ["/usr", "/bin", "/lib", "/lib64"];

/// The environment variables a command conventionally needs in order to start.
///
/// Exact names rather than an `LC_*` prefix: a glob would need a second grammar
/// on the helper wire for one convenience, and a caller wanting another `LC_`
/// variable can name it.
const STANDARD_ENV_NAMES: [&str; 7] = ["PATH", "HOME", "TERM", "LANG", "LC_ALL", "LC_CTYPE", "TZ"];

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
/// Three booleans rather than Landlock bits or `FsGuard` buckets. The reason is
/// layering, not convenience: a table carrying the kernel's rights, the guard's
/// buckets and the helper's flag spellings together — which is how this was first
/// proposed — would pull three downstream vocabularies into the one type that has
/// none, so `policy.rs` would depend on the `landlock` crate and on how a child
/// process is invoked. (`AccessFs::from_read` not being a `const fn` also rules
/// out a literal `const` table, but that is the incidental reason, and a const
/// workaround would not make the coupling a good idea.)
///
/// Each layer maps these onto its own vocabulary instead: `helper.rs` into
/// `BitFlags<AccessFs>`, `fs_guard.rs` into its readable/writable roots. **Every
/// consumer destructures this struct rather than reading its fields**, so a right
/// added here fails to compile at each site that has to map it — which is the
/// irreducible residue of two mechanisms that cannot speak each other's language.
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
    /// derive their own tables. What makes a forgotten axis a build failure is
    /// not this array but the exhaustive `match` that each site unable to derive
    /// its answer pairs with the loop — the audit record's counts, and
    /// `SandboxRun::paths`.
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
    /// Environment variable *names* the command may inherit. Never values: a
    /// policy says what is permitted, and the value is read from the harness's
    /// own environment when the command is spawned.
    env: Vec<String>,
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

    /// Environment variable names the process may inherit.
    ///
    /// Names, not values. Everything not listed here is dropped before the
    /// command starts, so a secret the harness holds is not something the
    /// filesystem policy has to express "not this" about — it simply does not
    /// cross.
    pub fn allowed_env(&self) -> &[String] {
        &self.env
    }

    /// Let the process inherit the variable called `name`.
    ///
    /// The one place a variable enters a policy. The value is not given here: it
    /// is read from the harness's own environment at spawn time, so a name that
    /// is unset there contributes nothing rather than an empty value.
    ///
    /// An empty name, or one containing `=` or a NUL, is skipped, on the same
    /// basis as [`allow_system_executables`] skipping a path this system lacks —
    /// none of them can name a variable that could ever be found, so dropping
    /// them is the conservative choice. Skipping here rather than refusing later
    /// is also what keeps the helper wire format round-tripping: nothing `encode`
    /// can emit is something `decode` rejects.
    ///
    /// A name is **not** deduplicated, matching the path grants, which do not
    /// either. Repeating one passes the same variable once, so the only trace is
    /// the audit count — which records the allowlist's length and says so.
    ///
    /// `sandbx`'s own `--allow-env` refuses what this skips, because a person at
    /// a terminal needs to be told; see `variable_name` in `sandbx-cli`.
    ///
    /// [`allow_system_executables`]: Self::allow_system_executables
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
    /// The environment counterpart of [`allow_system_executables`], and needed
    /// for the same reason: with an empty allowlist there is no `PATH`, and a
    /// program named without a leading `/` is then looked up in whatever default
    /// the thing doing the lookup falls back to. Which is not one answer — the
    /// failure is partial either way, and that is what makes it confusing:
    ///
    /// - A direct spawn goes through `execvp`, which uses the C library's
    ///   fallback. On glibc that is `confstr(_CS_PATH)`, i.e. `/bin:/usr/bin`.
    /// - A spawn through a shell gets the shell's own compiled-in default
    ///   instead, which is wider — dash and bash both include `/usr/local/bin`
    ///   and the `sbin` directories.
    ///
    /// So `cat` starts in both cases, and a program in `~/.cargo/bin` starts in
    /// neither. The symptom is `No such file or directory` for one program and
    /// not the next, naming neither the cause nor the fix, which is worse than a
    /// flat failure would be.
    ///
    /// A caller that always passes an absolute program path does not need this.
    /// Every test in `sandbx-core` does exactly that, which is why the default
    /// stays empty.
    ///
    /// Deliberately narrow: what a shell and a libc need to behave — `PATH`,
    /// `HOME`, `TERM`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TZ` — and nothing that
    /// conventionally carries a credential. Anything else is named one at a time
    /// through [`allow_env`].
    ///
    /// [`allow_env`]: Self::allow_env
    /// [`allow_system_executables`]: Self::allow_system_executables
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
    /// gained a path-scoped right for this in ABI V9 (Linux 7.1), and a
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
