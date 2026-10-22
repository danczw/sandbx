//! The host-side entry into helper mode: the two argv flags, and the handoff. Must run
//! before anything else in a `main`. A path out of here that neither runs the command nor
//! reports why not is a command that runs unrestricted, which is why both helper stages
//! return `Infallible` on success and every arm below is exhaustive.

use std::ffi::OsString;

/// Argument that marks a process as running in helper mode; the host binary checks for it
/// before doing anything else and hands off to [`with_helper_dispatch`].
pub const HELPER_FLAG: &str = "--sandbx-core-exec";

/// Argument that marks a process as the inner stage of helper mode. Internal protocol:
/// the supervisor started by [`HELPER_FLAG`] re-execs this binary with this flag once the
/// namespaces exist, making that child PID 1 of the new PID namespace. Public only so a
/// test can invoke the inner stage directly; elsewhere it runs a command without the
/// namespaces confining it. The pid it carries is checked for liveness, not authorization
/// — what confines the command is namespaces, seccomp and Landlock.
pub const HELPER_INNER_FLAG: &str = "--sandbx-core-exec-inner";

/// How a helper process announces, on its own stderr, that it refused. A const because the
/// parent strips it back off when it lifts that stderr into
/// [`SandboxError::HelperRefused`](crate::SandboxError::HelperRefused), and a writer and a
/// stripper that spell it twice drift apart.
pub(crate) const HELPER_FAILURE_PREFIX: &str = "sandbx: sandbox helper failed: ";

/// Run helper mode if `argv[1]` is one of the two flags, else `ordinary_main`. Call first
/// in `main`, before any threads start; it cannot enforce that. A failure exits non-zero;
/// one while waiting on the inner stage may follow the command running, restricted.
#[must_use = "a helper run that failed must exit non-zero"]
pub fn with_helper_dispatch<I, F>(argv: I, ordinary_main: F) -> std::process::ExitCode
where
    I: IntoIterator<Item = OsString>,
    F: FnOnce() -> std::process::ExitCode,
{
    let argv: Vec<String> = argv
        .into_iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();

    // argv[0] is this program's own name.
    let Some((flag, helper_args)) = argv.get(1..).and_then(<[String]>::split_first) else {
        return ordinary_main();
    };

    let error = match flag.as_str() {
        HELPER_FLAG => match crate::helper::exec_sandboxed(helper_args) {
            Err(error) => error,
        },
        HELPER_INNER_FLAG => match crate::helper::exec_inner(helper_args) {
            Err(error) => error,
        },
        _ => return ordinary_main(),
    };
    eprintln!("{HELPER_FAILURE_PREFIX}{error}");
    std::process::ExitCode::FAILURE
}
