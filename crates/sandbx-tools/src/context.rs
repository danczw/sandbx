use sandbx_core::{FsGuard, SandboxPolicy, SandboxedCommand};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::ToolLimits;

/// How long a tool's command may run before it is killed.
///
/// The tighter end, since too long silently fails to catch the wedge this exists
/// for. The known pressure point is a cold `cargo build` on a large workspace.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(90);

/// What a tool is allowed to touch, and the machinery for enforcing it.
///
/// Built once per session and shared by every tool call. Holds both halves of the
/// sandbox because the built-ins split across them: in-process tools check paths
/// through [`FsGuard`], `bash` spawns through the kernel-enforced path. The policy
/// itself is private, reachable only as a configured
/// [`sandboxed_command`](Self::sandboxed_command), which is what keeps that split
/// enforced.
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    guard: FsGuard,
    policy: SandboxPolicy,
    helper: Option<PathBuf>,
    limits: ToolLimits,
    timeout: Duration,
    session: Option<String>,
}

impl ExecutionContext {
    /// Resolve `policy` into a context tools can execute against.
    ///
    /// Nothing is added on the caller's behalf: `bash` needs
    /// [`SandboxPolicy::allow_system_executables`] to start anything, and runs with
    /// exactly the environment the policy names — none by default, so no `PATH` and
    /// no `HOME`. The ordinary pair is
    /// `allow_system_executables().allow_standard_env()`; a credential is named with
    /// [`SandboxPolicy::allow_env`].
    pub fn new(policy: SandboxPolicy) -> Self {
        Self::build(policy, None)
    }

    /// [`new`](Self::new), naming the session every record of this context's work carries —
    /// each spawn's pair, and the `rooted_access` degradation the guard may report as it is
    /// built.
    ///
    /// A constructor and not a setter, which is the whole reason this exists: the guard
    /// reports while it is *built*, so a context told its session afterwards has already
    /// emitted a record disclaiming one. The caller therefore has to hold a session before
    /// it builds a context — `sandbx-cli` opens one ahead of deriving the policy, since
    /// nothing may come between that derivation and this call (#249).
    pub fn for_session(policy: SandboxPolicy, session: impl Into<String>) -> Self {
        Self::build(policy, Some(session.into()))
    }

    /// Both constructors, so the guard cannot be built one way on one path.
    ///
    /// A spelling and not a `SessionId`: the type lives in `sandbx-session-id`, and taking
    /// it would be this crate's second dependency for a value it only passes along.
    fn build(policy: SandboxPolicy, session: Option<String>) -> Self {
        Self {
            guard: match &session {
                Some(id) => FsGuard::for_session(&policy, id),
                None => FsGuard::new(&policy),
            },
            policy,
            helper: None,
            limits: ToolLimits::default(),
            timeout: DEFAULT_TIMEOUT,
            session,
        }
    }

    /// Spawn through a specific sandbox helper instead of re-executing the current
    /// binary, which the default assumes calls `sandbx_core::with_helper_dispatch`
    /// at startup — the shipped `sandbx` does, a test harness does not.
    #[must_use]
    pub fn with_helper(mut self, path: impl AsRef<Path>) -> Self {
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
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
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
    /// [`FsGuard`] hands back. Timeout, helper and session are applied here so a second
    /// spawning built-in cannot forget them.
    #[must_use]
    pub fn sandboxed_command(&self, program: impl Into<String>) -> SandboxedCommand {
        let mut command = SandboxedCommand::new(program, self.policy.clone()).timeout(self.timeout);
        if let Some(helper) = &self.helper {
            command = command.helper(helper);
        }
        if let Some(session) = &self.session {
            command = command.session(session);
        }
        command
    }
}
