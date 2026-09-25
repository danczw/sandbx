//! Applies a sandbox policy to itself, then becomes the requested command.
//!
//! Usage: `sandbx-helper [--ro PATH]... [--rw PATH]... [--allow-network] -- PROGRAM [ARGS]...`
//!
//! Exists as a standalone binary so the enforcement path can be tested
//! end-to-end. In a shipped echo, the `echo` binary re-execs itself into the
//! same [`sandbx_core::exec_sandboxed`] entry point rather than requiring this
//! to be installed alongside.

fn main() -> std::process::ExitCode {
    // Goes through the same dispatch the shipped `echo` binary uses, so this
    // binary and production exercise one code path rather than two.
    //
    // In helper mode this never returns — the process image is replaced. Any
    // return means failure, and the command must NOT be run: falling through to
    // an unrestricted execution is the exact failure the sandbox exists to
    // prevent.
    if let Some(error) = sandbx_core::dispatch_helper_mode(std::env::args_os()) {
        eprintln!("sandbx-helper: {error}");
        return std::process::ExitCode::FAILURE;
    }

    eprintln!(
        "sandbx-helper: expected {} as the first argument",
        sandbx_core::HELPER_FLAG
    );
    std::process::ExitCode::FAILURE
}
