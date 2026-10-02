//! A binary that dispatches into sandbox helper mode, for tests.
//!
//! `SandboxedCommand` defaults to re-executing the current binary with
//! [`sandbx_core::HELPER_FLAG`], which assumes that binary calls
//! [`sandbx_core::dispatch_helper_mode`] first; a test harness does not.

fn main() -> std::process::ExitCode {
    // Must come first: in helper mode this never returns.
    match sandbx_core::dispatch_helper_mode(std::env::args_os()) {
        sandbx_core::HelperDispatch::Failed(error) => {
            eprintln!("sandbox helper: {error}");
            std::process::ExitCode::FAILURE
        }
        sandbx_core::HelperDispatch::NotHelperMode => {
            eprintln!("this binary only runs in sandbox helper mode");
            std::process::ExitCode::FAILURE
        }
    }
}
