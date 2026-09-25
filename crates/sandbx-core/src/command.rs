use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::{HelperArgs, SandboxError, SandboxPolicy};

/// Argument that marks a process as running in helper mode.
///
/// The host binary checks for this before doing anything else and, when present,
/// hands off to [`crate::exec_sandboxed`].
pub const HELPER_FLAG: &str = "--sandbx-core-exec";

/// A command that runs under a [`SandboxPolicy`].
///
/// The only sanctioned way for sandbx to execute anything. Rather than restricting
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
    timeout: Option<Duration>,
}

/// How often the timed path checks whether the child has exited.
///
/// `std::process` offers no timed wait, so the deadline is enforced by polling.
/// Short enough that a killed command is reclaimed promptly, long enough that
/// waiting costs nothing measurable.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// How long the pipe readers get once the command itself is gone.
///
/// Anything still holding a write-end by then escaped the process group kill,
/// so waiting on it is waiting on a process that has already shown it does not
/// cooperate. Long enough that output in flight is not lost, short enough that
/// no command can use it to stall its caller.
const DRAIN_GRACE: Duration = Duration::from_millis(200);

impl SandboxedCommand {
    /// Prepare `program` to run under `policy`.
    pub fn new(program: impl Into<String>, policy: SandboxPolicy) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            policy,
            helper: None,
            timeout: None,
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

    /// Kill the command if it has not finished within `limit`.
    ///
    /// Unset by default, which keeps the plain blocking behaviour. Callers that
    /// cannot afford to wait forever — anything driving an agent — should set
    /// one; an interactive caller at a terminal already has Ctrl-C.
    #[must_use]
    pub fn timeout(mut self, limit: Duration) -> Self {
        self.timeout = Some(limit);
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
    ///
    /// Blocks until the command exits, or — when [`timeout`] is set — until the
    /// limit expires, at which point the command is killed and
    /// [`SandboxError::TimedOut`] is returned.
    ///
    /// [`timeout`]: Self::timeout
    pub fn output(&self) -> Result<std::process::Output, SandboxError> {
        let (helper, argv) = self.command_line()?;

        crate::AuditEvent::spawned(&self.program, &self.policy).emit();

        match self.timeout {
            // Untouched from before the timeout existed: `output()` handles
            // reading both pipes concurrently, which is the part that is easy to
            // get wrong. Callers who set no limit get exactly what they got.
            None => {
                // The workspace bans `Command::new` so nothing can execute around
                // the sandbox. This spawns the helper, which restricts itself
                // before becoming the command — the sanctioned path, not a bypass.
                #[allow(clippy::disallowed_methods)]
                std::process::Command::new(&helper)
                    .args(&argv)
                    .output()
                    .map_err(|source| SandboxError::SpawnFailed {
                        detail: "could not start the sandbox helper",
                        source,
                    })
            }
            Some(limit) => run_with_deadline(&helper, &argv, limit),
        }
    }
}

/// Spawn the helper and wait for it, giving up after `limit`.
///
/// `std::process` has no timed wait, so this cannot use `output()`: it spawns,
/// drains both pipes on their own threads, and polls for exit until the deadline.
#[cfg(target_os = "linux")]
fn run_with_deadline(
    helper: &Path,
    argv: &[String],
    limit: Duration,
) -> Result<std::process::Output, SandboxError> {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;

    let spawn_failed = |source| SandboxError::SpawnFailed {
        detail: "could not start the sandbox helper",
        source,
    };

    // Its own process group, so the kill below reaches descendants too.
    #[allow(clippy::disallowed_methods)]
    let mut child = std::process::Command::new(helper)
        .args(argv)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(spawn_failed)?;

    // Captured now, while the child is definitely unreaped. `try_wait` reaps it
    // on success, after which `child.id()` names a pid that may already have
    // been recycled — a stale value to aim a signal with.
    let group = child.id();

    // Both pipes must be drained concurrently. A single thread reading stdout to
    // EOF deadlocks as soon as the command fills the stderr buffer, and vice
    // versa.
    let out = drain(child.stdout.take());
    let err = drain(child.stderr.take());

    let deadline = Instant::now() + limit;
    let finished = loop {
        match child.try_wait().map_err(spawn_failed)? {
            Some(status) => break Some(status),
            None if Instant::now() >= deadline => break None,
            None => std::thread::sleep(POLL_INTERVAL),
        }
    };

    // On *both* paths, not just the timeout. A command is free to background
    // work and exit well inside its deadline; whatever it left behind inherited
    // the pipe write-ends, so without this the readers below never see EOF and
    // the deadline — already satisfied — never rescues the call.
    kill_group(group);

    let status = match finished {
        Some(status) => status,
        None => {
            // Reap the killed child rather than leaving a zombie.
            let _ = child.wait();
            settle(&out.0, &err.0);
            return Err(SandboxError::TimedOut { after: limit });
        }
    };

    settle(&out.0, &err.0);

    Ok(std::process::Output {
        status,
        stdout: take(&out.1),
        stderr: take(&err.1),
    })
}

/// Give the pipe readers a bounded chance to finish, then stop waiting.
///
/// A process group is advisory: one `setsid` call leaves it, so `kill_group`
/// cannot promise the pipes are closed. Waiting on them unconditionally would
/// hand any command an easy way to block its caller forever — which is the
/// failure this whole function exists to prevent. Bounding the wait makes the
/// guarantee hold no matter what the command does; the cost is that output
/// still in flight past the grace period is dropped.
#[cfg(target_os = "linux")]
fn settle(readers: &std::thread::JoinHandle<()>, more: &std::thread::JoinHandle<()>) {
    let until = Instant::now() + DRAIN_GRACE;
    while Instant::now() < until && !(readers.is_finished() && more.is_finished()) {
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Take what a reader has collected so far.
#[cfg(target_os = "linux")]
fn take(buffer: &std::sync::Arc<std::sync::Mutex<Vec<u8>>>) -> Vec<u8> {
    // A panicking reader poisons the lock but leaves the bytes it already read
    // intact, and partial output beats none.
    buffer
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Read one pipe on its own thread, into a buffer the caller can take early.
///
/// Separate threads rather than one: reading stdout to EOF from the same thread
/// that must also read stderr deadlocks the moment the command fills whichever
/// buffer is not being drained.
///
/// Chunked into a shared buffer rather than `read_to_end`, so that abandoning a
/// reader still yields whatever it managed to read. `read_to_end` holds the
/// bytes inside the thread until it returns, which is exactly when it cannot.
#[cfg(target_os = "linux")]
#[allow(clippy::type_complexity)]
fn drain<R>(
    pipe: Option<R>,
) -> (
    std::thread::JoinHandle<()>,
    std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
)
where
    R: std::io::Read + Send + 'static,
{
    use std::sync::{Arc, Mutex, PoisonError};

    let buffer = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&buffer);

    let handle = std::thread::spawn(move || {
        let Some(mut pipe) = pipe else { return };
        let mut chunk = [0u8; 8192];
        loop {
            match std::io::Read::read(&mut pipe, &mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(read) => sink
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .extend_from_slice(&chunk[..read]),
            }
        }
    });

    (handle, buffer)
}

/// SIGKILL a process group.
///
/// `SIGKILL` rather than a `SIGTERM` grace period: a command that has already
/// blown its deadline has not earned more time, and a grace period is a second
/// knob plus a second delay.
///
/// Best-effort by nature. The group is advisory — a descendant that calls
/// `setsid` is out of reach — so this reclaims well-behaved processes rather
/// than guaranteeing none survive. A PID namespace would make it unescapable.
#[cfg(target_os = "linux")]
fn kill_group(group: u32) {
    use nix::sys::signal::{Signal, killpg};
    use nix::unistd::Pid;

    // `process_group(0)` made the child its own group leader, so its pid is the
    // group id. The kernel keeps that number reserved while the group still has
    // members, so it cannot name someone else's group here. An error means the
    // group is already empty, which is the outcome being asked for.
    if let Ok(pid) = i32::try_from(group) {
        let _ = killpg(Pid::from_raw(pid), Signal::SIGKILL);
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
