use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::{HelperArgs, SandboxError, SandboxPolicy};

/// Argument that marks a process as running in helper mode; the host binary checks for it
/// before doing anything else and hands off to [`dispatch_helper_mode`].
pub const HELPER_FLAG: &str = "--sandbx-core-exec";

/// Argument that marks a process as the *inner* stage of helper mode.
///
/// Internal protocol between the two helper stages: the supervisor started by
/// [`HELPER_FLAG`] re-execs this binary with this flag once the namespaces exist, making
/// that child PID 1 of the new PID namespace. Public only so a test can invoke the inner
/// stage directly; elsewhere it runs a command without the namespaces confining it.
///
/// The check behind it is *liveness*, not authorization: the inner stage confirms the pid it
/// was handed is still its parent, so someone is positioned to reap it, and a parent passing
/// its own pid satisfies it. What confines the command is namespaces, seccomp and Landlock.
pub const HELPER_INNER_FLAG: &str = "--sandbx-core-exec-inner";

/// A command that runs under a [`SandboxPolicy`].
///
/// The only sanctioned way for sandbx to execute anything. Restricting a child directly
/// would need unsafe work between `fork` and `exec`, so instead a helper restricts *itself*
/// in two stages: the first creates the namespaces, including a PID namespace, and re-execs
/// into the second, which is therefore PID 1 of it and restricts itself before becoming the
/// command — so the command and its descendants live in a namespace that ends when the call
/// does (see `kill_group`). The helper defaults to this same executable re-run with
/// [`HELPER_FLAG`]; [`SandboxedCommand::helper`] overrides that.
#[derive(Debug, Clone)]
pub struct SandboxedCommand {
    program: String,
    args: Vec<String>,
    policy: SandboxPolicy,
    helper: Option<PathBuf>,
    timeout: Option<Duration>,
}

/// How often the timed path polls for the child's exit, `std::process` having no timed wait.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// How long the pipe readers get once the command itself is gone.
///
/// The PID namespace normally closes the pipes — every descendant dies with the command, so
/// nothing holds a write-end. A bound on the wait rather than a claim about who still runs.
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
    /// Mainly for tests, whose harness `main` has no dispatch of its own.
    #[must_use]
    pub fn helper(mut self, path: impl AsRef<Path>) -> Self {
        self.helper = Some(path.as_ref().to_path_buf());
        self
    }

    /// Kill the command if it has not finished within `limit`; unset by default.
    #[must_use]
    pub fn timeout(mut self, limit: Duration) -> Self {
        self.timeout = Some(limit);
        self
    }

    /// Build the exact command line that will be run.
    ///
    /// Spawning it yourself carries one obligation: the argv contains `AUDIT_STDIN_FLAG`,
    /// telling the helper its stdin is a channel to write audit records to, and only
    /// [`output`](Self::output) sets that pipe up. Give it a writable pipe on stdin and
    /// decode what comes back, or drop that argument — with fd 0 a terminal, a degradation
    /// is written there as if the command had produced it.
    pub fn command_line(&self) -> Result<(PathBuf, Vec<String>), SandboxError> {
        // Explicit or re-exec'd, every helper speaks the same protocol; a second calling
        // convention would be a silent mismatch whenever a binary implemented the other.
        let helper = match &self.helper {
            Some(path) => path.clone(),
            None => current_exe()?,
        };
        // Ahead of the policy, where `exec_sandboxed` splits it off before decoding, and
        // unconditional because both spawn paths below set the pipe up.
        let mut argv = vec![
            HELPER_FLAG.to_string(),
            crate::helper::AUDIT_STDIN_FLAG.to_string(),
        ];

        argv.extend(HelperArgs::encode(&self.policy, &self.program, &self.args));
        Ok((helper, argv))
    }

    /// Run the command to completion and collect its output.
    ///
    /// Blocks until the command exits, or — with a [`timeout`](Self::timeout) set — until
    /// the limit expires, which kills it and returns [`SandboxError::TimedOut`].
    pub fn output(&self) -> Result<std::process::Output, SandboxError> {
        let (helper, argv) = self.command_line()?;

        crate::AuditEvent::spawned(&self.program, &self.policy).emit();

        match self.timeout {
            None => {
                let (audit, write_end) = audit_channel()?;

                // `spawn::command` narrows the environment as it builds, so a secret never
                // enters even this helper, whose `/proc/<pid>/environ` is readable.
                let mut helper = crate::spawn::command(&helper, &self.policy);
                helper
                    .args(&argv)
                    .stdin(std::process::Stdio::from(write_end));

                let output = helper.output().map_err(|source| SandboxError::SpawnFailed {
                    detail: "could not start the sandbox helper",
                    source,
                });

                // Dropped before the channel is read, and that ordering is what makes the
                // read terminate: the `Command` owns this process's copy of the write end.
                drop(helper);
                record_degradations(audit);

                output
            }
            Some(limit) => run_with_deadline(&helper, &argv, &self.policy, limit),
        }
    }
}

/// A pipe for the helper to report degraded hardening on.
///
/// The write end becomes the helper's stdin — the one descriptor std can hand a child
/// without `unsafe`, which this crate forbids, at the cost of the stdin slot. Stage 1
/// replaces it with `null` before spawning anything, so the command never holds it.
fn audit_channel() -> Result<(std::io::PipeReader, std::io::PipeWriter), SandboxError> {
    std::io::pipe().map_err(|source| SandboxError::SpawnFailed {
        detail: "could not open a channel for the sandbox helper's audit records",
        source,
    })
}

/// Read what the helper reported and put it on the audit trail.
///
/// Emitted here because this is the process with a subscriber; the helper installs none, and
/// cannot without writing sandbx's records into the command's own output. Reads to EOF with
/// the helper already waited on, so nothing drains the pipe while it writes — safe only
/// because `degradation::encode` bounds the records, a channel that could outgrow the pipe
/// buffer deadlocking the run it reports on.
fn record_degradations(mut audit: std::io::PipeReader) {
    use std::io::Read;

    let mut records = String::new();
    if audit.read_to_string(&mut records).is_err() {
        return;
    }

    for (step, detail) in crate::degradation::decode(&records) {
        crate::AuditEvent::degraded(step.label(), detail).emit();
    }
}

/// Spawn the helper and wait for it, giving up after `limit`.
///
/// `std::process` has no timed wait, so not `output()`: this drains both pipes on their own
/// threads and polls for exit until the deadline.
fn run_with_deadline(
    helper: &Path,
    argv: &[String],
    policy: &SandboxPolicy,
    limit: Duration,
) -> Result<std::process::Output, SandboxError> {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;

    let spawn_failed = |source| SandboxError::SpawnFailed {
        detail: "could not start the sandbox helper",
        source,
    };

    let (audit, write_end) = audit_channel()?;

    // Its own process group, so the kill below reaches descendants too.
    let mut command = crate::spawn::command(helper, policy);
    command
        .args(argv)
        .stdin(Stdio::from(write_end))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);

    let mut child = command.spawn().map_err(spawn_failed)?;

    // This process's copy of the write end would keep the channel from reaching EOF.
    drop(command);

    // Captured while the child is definitely unreaped: `try_wait` reaps it on success,
    // after which `child.id()` names a pid that may already have been recycled.
    let group = child.id();

    // Concurrently, or a reader blocked on stdout deadlocks on a full stderr buffer.
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

    // On *both* paths, not just the timeout: a command may background work and exit well
    // inside its deadline, and what it left behind inherited the pipe write-ends, so the
    // readers would never see EOF.
    kill_group(group);

    let status = match finished {
        Some(status) => status,
        None => {
            let _ = child.wait();
            settle(&out.0, &err.0);
            // Recorded even though the run is refused: the hardening degraded before the
            // command started, so it holds of the attempt however it ended.
            record_degradations(audit);
            return Err(SandboxError::TimedOut { after: limit });
        }
    };

    settle(&out.0, &err.0);
    record_degradations(audit);

    Ok(std::process::Output {
        status,
        stdout: take(&out.1),
        stderr: take(&err.1),
    })
}

/// Give the pipe readers a [`DRAIN_GRACE`] chance to finish, then stop waiting; output
/// still in flight past the grace period is dropped.
fn settle(readers: &std::thread::JoinHandle<()>, more: &std::thread::JoinHandle<()>) {
    let until = Instant::now() + DRAIN_GRACE;
    while Instant::now() < until && !(readers.is_finished() && more.is_finished()) {
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Take what a reader has collected so far.
///
/// A reader that outlived `settle`'s grace period may still append after this returns, but
/// those bytes are lost either way, so taking loses nothing a copy would keep.
fn take(buffer: &std::sync::Arc<std::sync::Mutex<Vec<u8>>>) -> Vec<u8> {
    // A panicking reader poisons the lock but leaves the bytes it read intact.
    std::mem::take(
        &mut *buffer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
}

/// Read one pipe on its own thread, into a buffer the caller can take early.
///
/// Chunked into a shared buffer rather than `read_to_end`, which holds the bytes inside the
/// thread until it returns — exactly when an abandoned reader cannot.
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

/// SIGKILL a process group, and with it the PID namespace inside it.
///
/// The group alone is advisory — a descendant that calls `setsid` leaves it. What makes this
/// unescapable is where the signal lands: the helper's supervisor stage is in this group and
/// never leaves it, and the command runs as PID 1 of a PID namespace bound to that
/// supervisor's lifetime, so when it dies the kernel SIGKILLs everything still in the
/// namespace — nothing can leave the namespace it was born into, `unshare`/`setns` denied.
fn kill_group(group: u32) {
    use nix::sys::signal::{Signal, killpg};
    use nix::unistd::Pid;

    // `process_group(0)` made the child its own group leader, so its pid is the group id,
    // reserved while the group has members — it cannot name someone else's. An error means
    // the group is already empty.
    if let Ok(pid) = i32::try_from(group) {
        let _ = killpg(Pid::from_raw(pid), Signal::SIGKILL);
    }
}

/// Locate this executable, for re-running it in helper mode.
pub(crate) fn current_exe() -> Result<PathBuf, SandboxError> {
    std::env::current_exe().map_err(|source| SandboxError::SpawnFailed {
        detail: "could not locate the running executable to re-exec as the sandbox helper",
        source,
    })
}

/// What [`dispatch_helper_mode`] decided.
///
/// Two outcomes, not three: becoming the command never returns, so there is no success
/// variant to ignore by accident.
#[derive(Debug)]
#[must_use = "a helper run that failed must not fall through to running the command"]
pub enum HelperDispatch {
    /// Not a helper invocation: an ordinary run, argv too short to carry a flag included.
    NotHelperMode,

    /// Helper mode ran and failed; no unrestricted execution occurred.
    ///
    /// Usually the command never started, the restrictions being applied before the `exec`;
    /// the exception is a failure while waiting on the inner stage, where it may have run
    /// but ran *with* them applied. Exit non-zero either way — falling through to run the
    /// command from here is the exact failure the sandbox exists to prevent.
    Failed(SandboxError),
}

/// Hand off to helper mode when this process was started with [`HELPER_FLAG`].
///
/// Call first thing in `main`, before any threads start: the helper restricts itself and
/// `exec`s, so anything set up beforehand is discarded anyway. In a binary with an ordinary
/// mode too, prefer [`with_helper_dispatch`], which owns the "exit non-zero" half.
pub fn dispatch_helper_mode<I>(argv: I) -> HelperDispatch
where
    I: IntoIterator<Item = OsString>,
{
    let argv: Vec<String> = argv
        .into_iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();

    // argv[0] is this program's own name.
    let Some((flag, helper_args)) = argv.get(1..).and_then(<[String]>::split_first) else {
        return HelperDispatch::NotHelperMode;
    };

    // Exhaustive `match` in each arm rather than `?`: the entry points return `Infallible`
    // on success, so this cannot gain a path that returns without either running the
    // command or reporting why not.
    match flag.as_str() {
        HELPER_FLAG => match crate::helper::exec_sandboxed(helper_args) {
            Err(error) => HelperDispatch::Failed(error),
        },
        HELPER_INNER_FLAG => match crate::helper::exec_inner(helper_args) {
            Err(error) => HelperDispatch::Failed(error),
        },
        _ => HelperDispatch::NotHelperMode,
    }
}

/// Dispatch helper mode first, then run `ordinary_main` if this was not one.
///
/// The failure half is what a hand-written `main` gets wrong: printing the error but
/// forgetting to return non-zero falls through to the ordinary path, and a fall-through here
/// is a command that runs unrestricted. It cannot enforce being called *first*.
pub fn with_helper_dispatch<I, F>(argv: I, ordinary_main: F) -> std::process::ExitCode
where
    I: IntoIterator<Item = OsString>,
    F: FnOnce() -> std::process::ExitCode,
{
    match dispatch_helper_mode(argv) {
        HelperDispatch::Failed(error) => {
            eprintln!("sandbx: sandbox helper failed: {error}");
            std::process::ExitCode::FAILURE
        }
        HelperDispatch::NotHelperMode => ordinary_main(),
    }
}
