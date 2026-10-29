//! A binary that dispatches into sandbox helper mode, for tests.
//!
//! `SandboxedCommand` defaults to re-executing the current binary with
//! [`sandbx_core::HELPER_FLAG`], which assumes that binary calls
//! [`sandbx_core::with_helper_dispatch`] first; a test harness does not.

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    // Must come first: in helper mode this returns only if the helper failed.
    sandbx_core::with_helper_dispatch(env::args_os(), || {
        eprintln!("this binary only runs in sandbox helper mode");
        ExitCode::FAILURE
    })
}
