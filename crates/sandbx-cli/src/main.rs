//! The `sandbx` binary: helper dispatch, then the command line.
//!
//! Holds only what needs a real process; the parsing and policy derivation it drives
//! live in the library half.

use clap::Parser;
use sandbx_cli::{Cli, Command};

fn main() -> std::process::ExitCode {
    // Must come before argument parsing: `SandboxedCommand` re-execs this same binary
    // as its helper, and in that mode the process restricts itself and becomes the
    // target command rather than falling through to here.
    sandbx_core::with_helper_dispatch(std::env::args_os(), || {
        // Inside the closure, never above it: in helper mode this process becomes the
        // sandboxed command, whose stderr the parent forwards verbatim, so a subscriber
        // installed above would write sandbx's records into that output. Helper mode has
        // no subscriber; its hardening steps report what degraded back over a pipe for
        // `SandboxedCommand` to emit against this one.
        if let Err(error) = sandbx_cli::logging::init() {
            eprintln!("sandbx: audit trail unavailable: {error}");
        }

        match Cli::parse().command {
            Command::SandboxRun(args) => report(args.execute(), 1),
            Command::AgentRun(args) => report(block_on(args.execute()), 1),
            Command::Hash(args) => report(args.execute(), 1),
            // 2, not 1: `auth status` already spends 1 on "no key anywhere", and a script
            // branching on that must not read a refused file as an absent one.
            Command::Auth(args) => report(args.execute(), 2),
        }
    })
}

/// Turn what a subcommand reported into an exit code, saying why on the way out.
///
/// `failure` is the code an `Err` exits with, which a subcommand reserving 1 for an answer
/// of its own has to move off.
fn report(result: Result<i32, impl std::fmt::Display>, failure: u8) -> std::process::ExitCode {
    match result {
        Ok(code) => std::process::ExitCode::from(u8::try_from(code).unwrap_or(failure)),
        Err(error) => {
            eprintln!("sandbx: {error}");
            std::process::ExitCode::from(failure)
        }
    }
}

/// Drive a turn to completion on a runtime built for it.
///
/// `new_current_thread` because `spawn_blocking` is all the loop asks of the scheduler;
/// `enable_all` for both drivers — the timer behind the per-round timeout, and the IO the
/// provider's connector opens on.
fn block_on(
    future: impl Future<Output = Result<i32, sandbx_cli::AgentError>>,
) -> Result<i32, sandbx_cli::AgentError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        // Named at the one call site that can produce it rather than by a blanket
        // `From`, which would label any later io error as this one.
        .map_err(sandbx_cli::AgentError::Runtime)?
        .block_on(future)
}
