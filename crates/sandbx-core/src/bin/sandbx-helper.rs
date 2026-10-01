//! Applies a sandbox policy to itself, then becomes the requested command.
//!
//! Usage: `sandbx-helper --sandbx-core-exec [POLICY]... -- PROGRAM [ARGS]...`,
//! where the policy flags are whatever [`sandbx_core::HelperArgs`] encodes — one
//! path flag per policy axis, plus `--allow-network` and `--allow-unix-sockets`.
//!
//! Runs in two stages, both of them this same binary. The invocation above is
//! stage one, the supervisor: it creates the namespaces and re-execs itself with
//! `--sandbx-core-exec-inner <supervisor-pid>` followed by the same arguments.
//! That second process is PID 1 of the new PID namespace, and it is the one that
//! applies seccomp and Landlock and becomes the command. The inner flag is the
//! protocol between the two, not something to invoke by hand — on its own it
//! refuses, having no supervisor to be reaped by.
//!
//! Exists as a standalone binary so the enforcement path can be tested
//! end-to-end. In a shipped sandbx, the `sandbx` binary re-execs itself into the
//! same [`sandbx_core::dispatch_helper_mode`] entry point rather than requiring this
//! to be installed alongside.

fn main() -> std::process::ExitCode {
    // In helper mode this never returns — the process image is replaced. Any
    // return means failure, and the command must NOT be run: falling through to
    // an unrestricted execution is the exact failure the sandbox exists to
    // prevent.
    match sandbx_core::dispatch_helper_mode(std::env::args_os()) {
        sandbx_core::HelperDispatch::Failed(error) => {
            eprintln!("sandbx-helper: {error}");
            std::process::ExitCode::FAILURE
        }
        // This binary has no ordinary mode, so "not helper mode" is a usage
        // error rather than something to carry on from.
        sandbx_core::HelperDispatch::NotHelperMode => {
            eprintln!(
                "sandbx-helper: expected {} as the first argument",
                sandbx_core::HELPER_FLAG
            );
            std::process::ExitCode::FAILURE
        }
    }
}
