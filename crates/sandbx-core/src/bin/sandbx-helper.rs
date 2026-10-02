//! Applies a sandbox policy to itself, then becomes the requested command.
//!
//! Usage: `sandbx-helper --sandbx-core-exec [POLICY]... -- PROGRAM [ARGS]...`, where the
//! policy flags are whatever [`sandbx_core::HelperArgs`] encodes.
//!
//! Two stages, both this same binary. The invocation above is the supervisor: it creates
//! the namespaces and re-execs itself with `--sandbx-core-exec-inner <supervisor-pid>` and
//! the same arguments. That second process is PID 1 of the new PID namespace and is the
//! one that applies seccomp and Landlock and becomes the command. The inner flag is the
//! protocol between the two, not something to invoke by hand — alone it refuses, having
//! no supervisor to be reaped by.
//!
//! A standalone binary so the enforcement path can be tested end-to-end; a shipped sandbx
//! re-execs itself into [`sandbx_core::dispatch_helper_mode`] instead.

fn main() -> std::process::ExitCode {
    // In helper mode this never returns: the image is replaced. Any return is a failure,
    // and the command must NOT be run — an unrestricted execution is the exact failure
    // the sandbox exists to prevent.
    match sandbx_core::dispatch_helper_mode(std::env::args_os()) {
        sandbx_core::HelperDispatch::Failed(error) => {
            eprintln!("sandbx-helper: {error}");
            std::process::ExitCode::FAILURE
        }
        // This binary has no ordinary mode, so "not helper mode" is a usage error.
        sandbx_core::HelperDispatch::NotHelperMode => {
            eprintln!(
                "sandbx-helper: expected {} as the first argument",
                sandbx_core::HELPER_FLAG
            );
            std::process::ExitCode::FAILURE
        }
    }
}
