//! Running a command under a policy: the builder, the audit channel, the deadline. Nothing
//! here restricts anything itself — what restricts is the helper this spawns, in a process
//! of its own.
//!
//! One module on purpose: the deadline drives the drain and the drain is
//! what reads the audit channel, so the three are one supervision sequence.

use std::io::{PipeReader, PipeWriter, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use std::{fs, io, mem, thread};

use crate::{HelperArgs, SandboxError, SandboxPolicy, Sha256Digest};

use super::dispatch::HELPER_FLAG;

/// A command that runs under a [`SandboxPolicy`]; the only sanctioned way for sandbx to
/// execute anything. A helper restricts itself in two stages, restricting a child directly
/// needing unsafe work between `fork` and `exec`; the command ends up the child of the init
/// of a namespace that dies with this call (`context/guide-process-lifetime.md`). The helper
/// defaults to this executable re-run with [`HELPER_FLAG`] through `/proc/self/exe`, which a
/// rename over the binary cannot redirect.
#[derive(Debug, Clone)]
pub struct SandboxedCommand {
    program: String,
    args: Vec<String>,
    policy: SandboxPolicy,
    helper: Option<PathBuf>,
    timeout: Option<Duration>,
    pin: Option<Sha256Digest>,
    session: Option<String>,
}

/// How often the timed path polls for the child's exit, `std::process` having no timed wait.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// How long the pipe readers get once the command itself is gone — a bound on the wait, not
/// a claim about who still holds a write end.
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
            pin: None,
            session: None,
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

    /// Use a specific helper executable instead of re-running this one. Mainly for tests,
    /// whose harness `main` has no dispatch of its own. A path and not an inode: a rename
    /// over it redirects the next spawn, which the default does not allow. Pass an
    /// absolute one — [`output`](Self::output) spawns from the policy's
    /// [`working_root`](SandboxPolicy::working_root), so a relative path resolves against
    /// that rather than against this process's own working directory.
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

    /// Name the session this runs under, so a record pairs with a transcript; unset by
    /// default, which is what `sandbox-run` is — it has no session to name.
    #[must_use]
    pub fn session(mut self, id: impl Into<String>) -> Self {
        self.session = Some(id.into());
        self
    }

    /// Refuse to run `program` unless its bytes hash to `digest`; unpinned by default. Covers
    /// the one `execve` sandbx performs and nothing the command then spawns itself, and
    /// requires an absolute `program`: the helper opens the file to hash it, so it resolves
    /// the name instead of libc (`context/decision-helper-audit-channel.md`).
    #[must_use]
    pub fn pin_sha256(mut self, digest: Sha256Digest) -> Self {
        self.pin = Some(digest);
        self
    }

    /// Build the exact command line that will be run. Spawning it yourself carries two
    /// obligations: the argv contains `AUDIT_STDIN_FLAG`, telling the helper its stdin is a
    /// channel for audit records, and only [`output`](Self::output) sets that pipe up — with
    /// fd 0 a terminal, a degradation is written there as if the command had produced it. And
    /// the start directory is not in the argv: `output` chdirs to the policy's
    /// [`working_root`](SandboxPolicy::working_root), so spawning from here inherits your own
    /// and may begin somewhere the policy refuses — spawn it from this process too, since the
    /// default helper path resolves against whichever process execs it.
    pub fn command_line(&self) -> Result<(PathBuf, Vec<String>), SandboxError> {
        // Here and not in `output`: an embedder spawning this argv itself has to meet the
        // same refusal, `SECURITY.md`'s claim being made at this level.
        if let Some(detail) = self.policy.unbounded_resolution() {
            return Err(SandboxError::UnboundedResolution { detail });
        }
        if let Some(granted) = self.policy.grant_bound_by_resolver() {
            return Err(SandboxError::GrantBoundByResolver {
                granted: granted.to_path_buf(),
            });
        }

        let helper = self.helper.clone().map_or_else(self_exe, Ok)?;
        // Ahead of the policy, where `exec_sandboxed` splits it off before decoding, and
        // unconditional because both spawn paths below set the pipe up.
        let mut argv = vec![
            HELPER_FLAG.to_string(),
            crate::helper::AUDIT_STDIN_FLAG.to_string(),
        ];

        argv.extend(HelperArgs::encode(
            &self.policy,
            &self.program,
            &self.args,
            self.pin,
        ));
        Ok((helper, argv))
    }

    /// Run the command to completion and collect its output. Blocks until the command exits,
    /// or — with a [`timeout`](Self::timeout) set — until the limit expires, which kills it
    /// and returns [`SandboxError::TimedOut`]. A helper stage that refused returns
    /// [`SandboxError::HelperRefused`] rather than the status it exited with, which is
    /// indistinguishable from the command's own.
    pub fn output(&self) -> Result<Output, SandboxError> {
        let (helper, argv) = self.command_line()?;
        let (audit, write_end) = audit_channel()?;

        // Minted here and not in `new`: this takes `&self`, so one builder can be run more
        // than once, and two runs are two pairs a reader has to tell apart.
        let spawn = crate::SpawnId::next();
        let session = self.session.as_deref();
        // Not `argv` above, which is the *helper's* — that one carries the encoded policy,
        // and a shadow here would put it on the trail.
        let command_args = crate::audit::args_field(&self.args);

        crate::AuditEvent::spawned(
            &self.program,
            &command_args,
            &spawn,
            session,
            &self.policy,
            self.pin.is_some(),
        )
        .emit();

        let result = match self.timeout {
            None => run_to_completion(&helper, &argv, &self.policy, write_end),
            Some(limit) => run_with_deadline(&helper, &argv, &self.policy, limit, write_end),
        };

        // Both paths wait before returning, so nothing drains the pipe while the helper
        // writes it — true on error paths too, since hardening degraded before the command
        // started and holds however the attempt ended.
        let refused = record_reports(audit, &spawn, session);

        // Exactly one of these per `spawned`, nothing between the two emits returning early.
        // The channel outranks the status: a command that never ran exited as the refusing
        // helper.
        match (&result, refused) {
            (_, Some(refusal)) => {
                crate::AuditEvent::failed(&self.program, &spawn, session, refusal.label())
            }
            (Ok(output), None) => {
                crate::AuditEvent::exited(&self.program, &spawn, session, &output.status)
            }
            (Err(error), None) => {
                crate::AuditEvent::failed(&self.program, &spawn, session, error.label())
            }
        }
        .emit();

        // A record replaces a status, never an error: an `Err` is sandbx's own account of a
        // kill it performed — keeping `timeout` out of the admitted set exists to not
        // suppress that.
        match (result, refused) {
            (Ok(output), Some(refusal)) => Err(refusal.relayed(&output.stderr)),
            (result, _) => result,
        }
    }
}

/// The helper, as both spawn paths build it: narrow environment, argv, start directory.
/// One builder so the start directory cannot be set on the undeadlined path and not the
/// timed one. Via `spawn::command`, so a secret never enters even this helper, whose
/// `/proc/<pid>/environ` is readable. Not set in `spawn::command` itself, which the inner
/// stage also calls to *start* the command: that would `chdir` with the ruleset already
/// installed, though both stages and the command inherit the directory regardless.
fn helper_command(helper: &Path, argv: &[String], policy: &SandboxPolicy) -> Command {
    let mut command = crate::spawn::command(helper, policy);
    command.args(argv);

    if let Some(root) = policy.working_root() {
        command.current_dir(root);
    }

    command
}

/// Spawn the helper and wait for it, with no deadline. `Command::output` reads both pipes
/// to EOF before it waits, so a command that never exits wedges the caller;
/// [`run_with_deadline`] is the path that cannot.
fn run_to_completion(
    helper: &Path,
    argv: &[String],
    policy: &SandboxPolicy,
    write_end: PipeWriter,
) -> Result<Output, SandboxError> {
    let mut command = helper_command(helper, argv, policy);
    command.stdin(Stdio::from(write_end));

    let output = command
        .output()
        .map_err(|source| SandboxError::SpawnFailed {
            detail: "could not start the sandbox helper",
            source,
        });

    // Dropped before the caller reads the channel, and that ordering is what makes the read
    // terminate: the `Command` owns this process's copy of the write end.
    drop(command);

    output
}

/// A pipe for the helper to report degraded hardening on. The write end becomes the
/// helper's stdin — the one descriptor std can hand a child without `unsafe`, which this
/// crate forbids. Stage 2 takes it off fd 0 before starting the command, so the command
/// never holds it (`context/decision-helper-audit-channel.md`).
fn audit_channel() -> Result<(PipeReader, PipeWriter), SandboxError> {
    io::pipe().map_err(|source| SandboxError::SpawnFailed {
        detail: "could not open a channel for the sandbox helper's audit records",
        source,
    })
}

/// Read what the helper reported, put it on the audit trail, and return the reason the
/// command never ran if there was one. Emitted here because this is the process with a
/// subscriber. Reads to EOF with the helper already waited on, which is safe only because
/// `degradation::encode` bounds the records: a channel that outgrew the pipe buffer would
/// deadlock the run it reports on.
///
/// `spawn` and `session` name the run each degradation weakened: these records fall between
/// a spawn and its outcome, so without them the middle of a run is attributed by position
/// while both ends are named (#249).
fn record_reports(
    mut audit: PipeReader,
    spawn: &crate::SpawnId,
    session: Option<&str>,
) -> Option<crate::HelperRefusal> {
    use std::io::Read;

    let mut records = String::new();
    if audit.read_to_string(&mut records).is_err() {
        return None;
    }

    let mut refused = None;
    for report in crate::degradation::decode(&records) {
        match report {
            crate::degradation::Report::Degraded(step, detail) => {
                crate::AuditEvent::degraded(step.label(), Some(spawn), session, detail).emit();
            }
            crate::degradation::Report::Failed(refusal) => {
                refused = Some(refusal);
            }
        }
    }

    refused
}

/// Spawn the helper and wait for it, giving up after `limit`. Not `output()`:
/// `std::process` has no timed wait, so this drains both pipes on their own threads and
/// polls for exit until the deadline.
fn run_with_deadline(
    helper: &Path,
    argv: &[String],
    policy: &SandboxPolicy,
    limit: Duration,
    write_end: PipeWriter,
) -> Result<Output, SandboxError> {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;

    let spawn_failed = |source| SandboxError::SpawnFailed {
        detail: "could not start the sandbox helper",
        source,
    };

    // Its own process group, so the kill below reaches descendants too.
    let mut command = helper_command(helper, argv, policy);
    command
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
        match child.try_wait() {
            Ok(Some(status)) => break Ok(Some(status)),
            Ok(None) if Instant::now() >= deadline => break Ok(None),
            Ok(None) => thread::sleep(POLL_INTERVAL),
            // Broken out and not returned, so the kill below is not skipped: the caller
            // reads the audit channel to an EOF only a dead helper gives.
            Err(source) => break Err(spawn_failed(source)),
        }
    };

    // On every path out of the loop, not just the timeout: a command may background work and
    // exit inside its deadline, leaving behind processes that inherited the pipe write ends
    // — the readers would otherwise never see EOF.
    kill_group(group);

    let status = match finished {
        Ok(Some(status)) => status,
        // A refused `try_wait` and a timeout leave the same thing behind: no status, a child
        // to reap and readers to let go.
        outcome => {
            let _ = child.wait();
            settle(&out.0, &err.0);
            return Err(outcome
                .err()
                .unwrap_or(SandboxError::TimedOut { after: limit }));
        }
    };

    settle(&out.0, &err.0);

    Ok(Output {
        status,
        stdout: take(&out.1),
        stderr: take(&err.1),
    })
}

/// Give the pipe readers a [`DRAIN_GRACE`] chance to finish, then stop waiting; output
/// still in flight past the grace period is dropped.
fn settle(readers: &JoinHandle<()>, more: &JoinHandle<()>) {
    let until = Instant::now() + DRAIN_GRACE;
    while Instant::now() < until && !(readers.is_finished() && more.is_finished()) {
        thread::sleep(POLL_INTERVAL);
    }
}

/// Take what a reader has collected so far; bytes a reader that outlived `settle`'s grace
/// period appends after this are lost either way.
fn take(buffer: &Arc<Mutex<Vec<u8>>>) -> Vec<u8> {
    // A panicking reader poisons the lock but leaves the bytes it read intact.
    mem::take(&mut *buffer.lock().unwrap_or_else(PoisonError::into_inner))
}

/// Read one pipe on its own thread, into a buffer the caller can take early. Chunked into
/// a shared buffer rather than `read_to_end`, which holds the bytes inside the thread
/// until it returns — exactly when an abandoned reader cannot.
#[allow(clippy::type_complexity)]
fn drain<R>(pipe: Option<R>) -> (JoinHandle<()>, Arc<Mutex<Vec<u8>>>)
where
    R: Read + Send + 'static,
{
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&buffer);

    let handle = thread::spawn(move || {
        let Some(mut pipe) = pipe else { return };
        let mut chunk = [0u8; 8192];
        loop {
            match pipe.read(&mut chunk) {
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

/// SIGKILL a process group, and with it the PID namespace inside it. The group alone is
/// advisory, a descendant that calls `setsid` leaving it; what makes this unescapable is
/// that the supervisor stage never leaves this group and the PID namespace is bound to its
/// lifetime (`context/guide-process-lifetime.md`).
fn kill_group(group: u32) {
    use nix::sys::signal::{Signal, killpg};
    use nix::unistd::Pid;

    // `process_group(0)` made the child its own group leader, so its pid is the group id,
    // reserved while the group has members and so cannot name someone else's; an error
    // means the group is already empty.
    if let Ok(pid) = i32::try_from(group) {
        let _ = killpg(Pid::from_raw(pid), Signal::SIGKILL);
    }
}

const SELF_EXE: &str = "/proc/self/exe";

/// The path to re-exec this process through, for running it in helper mode. A link to the
/// inode this process was loaded from rather than the install path, so a replacement
/// renamed over the binary cannot redirect the next spawn. The `read_link` only proves
/// `/proc` is mounted; the link itself is what gets exec'd.
pub(crate) fn self_exe() -> Result<PathBuf, SandboxError> {
    fs::read_link(SELF_EXE).map_err(|source| SandboxError::SpawnFailed {
        detail: "could not locate the running executable to re-exec as the sandbox helper",
        source,
    })?;

    Ok(PathBuf::from(SELF_EXE))
}

#[cfg(test)]
#[path = "command_run_tests.rs"]
mod tests;
