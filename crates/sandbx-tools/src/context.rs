use sandbx_core::{FsGuard, SandboxPolicy, SandboxedCommand};

use crate::OutputLimits;

/// How long a tool's command may run before it is killed.
///
/// Deliberately the tighter end: there is no agent caller yet to measure
/// against, and a limit that is too short announces itself the first time real
/// work dies, where one that is too long silently fails to catch the wedge it
/// exists for. The known pressure point is a cold `cargo build` on a large
/// workspace; raise this when that actually bites.
pub const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);

/// What a tool is allowed to touch, and the machinery for enforcing it.
///
/// Built once per session from a [`SandboxPolicy`] and shared by every tool
/// call. Holds both halves of the sandbox because the built-ins split across
/// them: native-Rust tools check paths through [`FsGuard`], while `bash` spawns
/// through the kernel-enforced path.
///
/// The policy is private, and reachable only as a configured
/// [`sandboxed_command`]. That is what keeps the split honest rather than
/// merely documented — see that method.
///
/// [`sandboxed_command`]: Self::sandboxed_command
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    guard: FsGuard,
    policy: SandboxPolicy,
    helper: Option<std::path::PathBuf>,
    limits: OutputLimits,
    timeout: std::time::Duration,
}

impl ExecutionContext {
    /// Resolve `policy` into a context tools can execute against.
    pub fn new(policy: SandboxPolicy) -> Self {
        Self {
            guard: FsGuard::new(&policy),
            policy,
            helper: None,
            limits: OutputLimits::default(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Spawn through a specific sandbox helper instead of re-executing the
    /// current binary.
    ///
    /// The default assumes the running binary calls
    /// `sandbx_core::dispatch_helper_mode` at startup, which the shipped `sandbx`
    /// does and a test harness does not.
    #[must_use]
    pub fn with_helper(mut self, path: impl AsRef<std::path::Path>) -> Self {
        self.helper = Some(path.as_ref().to_path_buf());
        self
    }

    /// Bound tool output differently from the defaults.
    #[must_use]
    pub fn with_limits(mut self, limits: OutputLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Bound how long a tool's command may run, instead of [`DEFAULT_TIMEOUT`].
    #[must_use]
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// How much tools may return.
    pub fn limits(&self) -> &OutputLimits {
        &self.limits
    }

    /// How long a tool's command may run before it is killed.
    pub fn timeout(&self) -> std::time::Duration {
        self.timeout
    }

    /// Path checks for tools that touch the filesystem in-process.
    pub fn guard(&self) -> &FsGuard {
        &self.guard
    }

    /// A command to spawn, with the policy, the helper and the timeout already
    /// applied.
    ///
    /// The only route to the policy, and deliberately one that spends it rather
    /// than lending it out. An accessor returning `&SandboxPolicy` let a native
    /// filesystem tool read the path lists and open files itself, bypassing the
    /// TOCTOU-safe handles [`FsGuard`] exists to hand back — the split was
    /// documented but nothing enforced it (#56). A tool can now spawn, or check
    /// paths through [`guard`]; neither hands it the lists.
    ///
    /// Applying the timeout and helper here rather than at each call site is the
    /// same argument one layer down: a second spawning built-in cannot forget
    /// what it never has to remember.
    ///
    /// [`guard`]: Self::guard
    #[must_use]
    pub fn sandboxed_command(&self, program: impl Into<String>) -> SandboxedCommand {
        let mut command = SandboxedCommand::new(program, self.policy.clone()).timeout(self.timeout);
        if let Some(helper) = &self.helper {
            command = command.helper(helper);
        }
        command
    }
}
