//! The `sandbx` binary: helper dispatch, then the command line.
//!
//! Holds only what needs a real process; the argument parsing and policy derivation
//! it drives live in the library half.

use clap::Parser;
use sandbx_cli::{Cli, Command};

fn main() -> std::process::ExitCode {
    // Dispatch must come before argument parsing: `SandboxedCommand` re-execs this
    // same binary as its helper, and in that mode the process restricts itself and
    // becomes the target command. A failed helper run ends the process inside the
    // wrapper rather than falling through to here.
    sandbx_core::with_helper_dispatch(std::env::args_os(), || {
        // Inside the closure, never above it: in helper mode this process becomes the
        // sandboxed command, whose stderr the parent forwards verbatim, so a
        // subscriber installed above would write sandbx's own records into the
        // sandboxed command's output. Helper mode therefore has no subscriber, and
        // the hardening steps that run there report what degraded back over a pipe
        // for `SandboxedCommand` to emit against this one. Warn and carry on: an
        // unrecorded run still beats no run.
        if let Err(error) = sandbx_cli::logging::init() {
            eprintln!("sandbx: audit trail unavailable: {error}");
        }

        match Cli::parse().command {
            Command::SandboxRun(args) => match args.execute() {
                Ok(code) => std::process::ExitCode::from(u8::try_from(code).unwrap_or(1)),
                Err(error) => {
                    eprintln!("sandbx: {error}");
                    std::process::ExitCode::FAILURE
                }
            },
        }
    })
}
