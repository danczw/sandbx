//! A binary that dispatches into sandbox helper mode, for tests.
//!
//! `SandboxedCommand` defaults to re-executing the current binary with
//! [`sandbx_core::HELPER_FLAG`], which assumes that binary calls
//! [`sandbx_core::dispatch_helper_mode`] first. A test harness does not, so
//! tests point at this instead — and in doing so exercise the same dispatch the
//! shipped `sandbx` binary will use.

fn main() -> std::process::ExitCode {
    // Must come first: in helper mode this never returns, and anything set up
    // beforehand would be discarded by the exec anyway.
    if let Some(error) = sandbx_core::dispatch_helper_mode(std::env::args_os()) {
        eprintln!("sandbox helper: {error}");
        return std::process::ExitCode::FAILURE;
    }

    eprintln!("this binary only runs in sandbox helper mode");
    std::process::ExitCode::FAILURE
}
