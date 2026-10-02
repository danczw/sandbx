use sandbx_core::{FsGuard, SandboxPolicy, SandboxedCommand};

use crate::ToolLimits;

/// How long a tool's command may run before it is killed.
///
/// The tighter end, since too long silently fails to catch the wedge this exists
/// for. The known pressure point is a cold `cargo build` on a large workspace.
pub const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);

/// What a tool is allowed to touch, and the machinery for enforcing it.
///
/// Built once per session from a [`SandboxPolicy`] and shared by every tool call.
/// Holds both halves of the sandbox because the built-ins split across them:
/// in-process tools check paths through [`FsGuard`], `bash` spawns through the
/// kernel-enforced path. The policy itself is private, reachable only as a
/// configured [`sandboxed_command`], which is what keeps that split enforced.
///
/// [`sandboxed_command`]: Self::sandboxed_command
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    guard: FsGuard,
    policy: SandboxPolicy,
    helper: Option<std::path::PathBuf>,
    limits: ToolLimits,
    timeout: std::time::Duration,
}

impl ExecutionContext {
    /// Resolve `policy` into a context tools can execute against.
    ///
    /// Nothing is added on the caller's behalf, including the parts a caller
    /// forgets: `bash` needs [`SandboxPolicy::allow_system_executables`] to start
    /// anything, and runs with exactly the environment the policy names — none by
    /// default, so no `PATH` and no `HOME` (a shell's compiled-in search path still
    /// finds `/usr/bin`, but `~/.cargo/bin` is missed and `git` misbehaves). The
    /// ordinary pair is `allow_system_executables().allow_standard_env()`; a
    /// credential is named with [`SandboxPolicy::allow_env`].
    pub fn new(policy: SandboxPolicy) -> Self {
        Self {
            guard: FsGuard::new(&policy),
            policy,
            helper: None,
            limits: ToolLimits::default(),
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

    /// Bound what tools may do and return differently from the defaults.
    #[must_use]
    pub fn with_limits(mut self, limits: ToolLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Bound how long a tool's command may run, instead of [`DEFAULT_TIMEOUT`].
    #[must_use]
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// How much tools may do, and how much they may return.
    pub fn limits(&self) -> &ToolLimits {
        &self.limits
    }

    /// Path checks for tools that touch the filesystem in-process.
    pub fn guard(&self) -> &FsGuard {
        &self.guard
    }

    /// A command to spawn, with the policy, the helper and the timeout already
    /// applied.
    ///
    /// The only route to the policy, and one that spends it rather than lending it
    /// out: an accessor returning `&SandboxPolicy` would let an in-process tool read
    /// the path lists and open files itself, bypassing the TOCTOU-safe handles
    /// [`FsGuard`] hands back. A tool can spawn, or check paths through [`guard`];
    /// neither hands it the lists. Timeout and helper are applied here so a second
    /// spawning built-in cannot forget them.
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
