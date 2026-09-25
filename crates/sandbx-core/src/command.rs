use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::{HelperArgs, SandboxError, SandboxPolicy};

/// Argument that marks a process as running in helper mode.
///
/// The host binary checks for this before doing anything else and, when present,
/// hands off to [`crate::exec_sandboxed`].
pub const HELPER_FLAG: &str = "--sandbx-core-exec";

/// A command that runs under a [`SandboxPolicy`].
///
/// The only sanctioned way for echo to execute anything. Rather than restricting
/// a child directly — which would require unsafe work in the fragile window
/// between `fork` and `exec` — this spawns a helper that restricts *itself* and
/// then becomes the command.
///
/// By default the helper is this same executable re-run with [`HELPER_FLAG`], so
/// no second binary has to be installed. [`helper`] overrides that.
///
/// [`helper`]: SandboxedCommand::helper
#[derive(Debug, Clone)]
pub struct SandboxedCommand {
    program: String,
    args: Vec<String>,
    policy: SandboxPolicy,
    helper: Option<PathBuf>,
}

impl SandboxedCommand {
    /// Prepare `program` to run under `policy`.
    pub fn new(program: impl Into<String>, policy: SandboxPolicy) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            policy,
            helper: None,
        }
    }

    /// Append one argument for the sandboxed program.
    #[must_use]
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Append several arguments for the sandboxed program.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Use a specific helper executable instead of re-running this one.
    ///
    /// Mainly for tests, which have a dedicated helper binary and no dispatch in
    /// the test harness's own `main`.
    #[must_use]
    pub fn helper(mut self, path: impl AsRef<Path>) -> Self {
        self.helper = Some(path.as_ref().to_path_buf());
        self
    }

    /// Build the exact command line that will be run.
    ///
    /// Exposed so tests can assert the policy survives into argv without having
    /// to spawn anything.
    pub fn command_line(&self) -> Result<(PathBuf, Vec<String>), SandboxError> {
        // Every helper speaks the same protocol: the flag, then the encoded
        // policy. An explicit helper is still a helper — giving it a different
        // calling convention meant two protocols and a silent mismatch when a
        // binary implemented the other one.
        let helper = match &self.helper {
            Some(path) => path.clone(),
            None => current_exe()?,
        };
        let mut argv = vec![HELPER_FLAG.to_string()];

        argv.extend(HelperArgs::encode(&self.policy, &self.program, &self.args));
        Ok((helper, argv))
    }

    /// Run the command to completion and collect its output.
    pub fn output(&self) -> Result<std::process::Output, SandboxError> {
        let (helper, argv) = self.command_line()?;

        crate::AuditEvent::spawned(&self.program, &self.policy).emit();

        // The workspace bans `Command::new` so nothing can execute around the
        // sandbox. This spawns the helper, which restricts itself before
        // becoming the command — the sanctioned path, not a bypass of it.
        #[allow(clippy::disallowed_methods)]
        std::process::Command::new(&helper)
            .args(&argv)
            .output()
            .map_err(|source| SandboxError::SpawnFailed {
                detail: "could not start the sandbox helper",
                source,
            })
    }
}

/// Locate this executable, for re-running it in helper mode.
fn current_exe() -> Result<PathBuf, SandboxError> {
    std::env::current_exe().map_err(|source| SandboxError::SpawnFailed {
        detail: "could not locate the running executable to re-exec as the sandbox helper",
        source,
    })
}

/// Hand off to helper mode when this process was started with [`HELPER_FLAG`].
///
/// Call first thing in `main`, before any threads start: the helper restricts
/// itself and `exec`s, so anything set up beforehand is discarded anyway.
///
/// Returns normally when this is an ordinary run. When it is a helper run it
/// either never returns, or returns the error that stopped it — in which case
/// the caller must exit non-zero rather than continue, since falling through
/// would run the command unrestricted.
pub fn dispatch_helper_mode<I>(argv: I) -> Option<SandboxError>
where
    I: IntoIterator<Item = OsString>,
{
    let argv: Vec<String> = argv
        .into_iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();

    // argv[0] is this program's own name.
    let rest = argv.get(1..)?;
    let (flag, helper_args) = rest.split_first()?;
    if flag != HELPER_FLAG {
        return None;
    }

    match crate::exec_sandboxed(helper_args) {
        Err(error) => Some(error),
    }
}
