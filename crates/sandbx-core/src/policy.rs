use std::path::{Path, PathBuf};

/// Where a system keeps the binaries and libraries a command needs to start.
const SYSTEM_EXECUTABLE_PATHS: [&str; 4] = ["/usr", "/bin", "/lib", "/lib64"];

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
}

impl SandboxPolicy {
    /// Paths the process may read.
    pub fn readable_paths(&self) -> &[PathBuf] {
        &self.readable
    }

    /// Paths the process may write.
    ///
    /// Writable does not imply readable — the two are granted separately, so a
    /// write-only drop directory stays unreadable.
    pub fn writable_paths(&self) -> &[PathBuf] {
        &self.writable
    }

    /// Paths the process may read *and* execute.
    ///
    /// Separate from [`readable_paths`] because execute is a distinct capability
    /// that no other grant confers: reading a file and running it are different
    /// powers, and only this axis carries the second.
    ///
    /// [`readable_paths`]: Self::readable_paths
    pub fn executable_paths(&self) -> &[PathBuf] {
        &self.executable
    }

    /// Whether the process may reach the network.
    pub fn allows_network(&self) -> bool {
        self.network
    }

    /// Grant read access to `path`.
    #[must_use]
    pub fn allow_read(mut self, path: impl AsRef<Path>) -> Self {
        self.readable.push(path.as_ref().to_path_buf());
        self
    }

    /// Grant write access to `path`.
    #[must_use]
    pub fn allow_write(mut self, path: impl AsRef<Path>) -> Self {
        self.writable.push(path.as_ref().to_path_buf());
        self
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
    pub fn allow_read_execute(mut self, path: impl AsRef<Path>) -> Self {
        self.executable.push(path.as_ref().to_path_buf());
        self
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
    /// This is the grant execute exists for. Everything else stays on
    /// [`allow_read`], which does not confer it.
    ///
    /// [`allow_read`]: Self::allow_read
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
    #[must_use]
    pub fn allow_network(mut self) -> Self {
        self.network = true;
        self
    }
}
