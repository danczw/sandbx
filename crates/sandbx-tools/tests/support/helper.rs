//! A binary that dispatches into sandbox helper mode, for tests.
//!
//! `SandboxedCommand` defaults to re-executing the current binary with
//! [`sandbx_core::HELPER_FLAG`], which assumes that binary calls
//! [`sandbx_core::with_helper_dispatch`] first; a test harness does not.

fn main() -> std::process::ExitCode {
    // Must come first: in helper mode this returns only if the helper failed.
    sandbx_core::with_helper_dispatch(std::env::args_os(), || {
        eprintln!("this binary only runs in sandbox helper mode");
        std::process::ExitCode::FAILURE
    })
}
