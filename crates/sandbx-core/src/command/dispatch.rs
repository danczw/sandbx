//! The host-side entry into helper mode: the two argv flags, and the handoff.
//!
//! Must run before anything else in a `main`. A path out of here that neither runs the
//! command nor reports why not is a command that runs unrestricted, which is why both entry
//! points return `Infallible` on success and every arm below is exhaustive.

use std::ffi::OsString;

use crate::SandboxError;

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
