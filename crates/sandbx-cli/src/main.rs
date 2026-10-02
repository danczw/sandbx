//! The `sandbx` binary: helper dispatch, then the command line.
//!
//! Holds only what needs a real process — the argument parsing and policy
//! derivation it drives live in the library half, where they are testable
//! without a sandbox-capable kernel.

use clap::Parser;
use sandbx_cli::{Cli, Command};

fn main() -> std::process::ExitCode {
    // Dispatch must come before argument parsing: `SandboxedCommand` re-execs
    // this same binary as its helper, and in that mode the process restricts
    // itself and becomes the target command. The wrapper owns the other half —
    // a failed helper run ends the process rather than falling through to here.
    sandbx_core::with_helper_dispatch(std::env::args_os(), || {
        // Inside the closure, never above it. In helper mode this same process
        // becomes the sandboxed command, and the parent captures and forwards its
        // stderr verbatim — a subscriber installed above would write sandbx's own
        // records into the output of the command being sandboxed. Warn and carry
        // on: an unrecorded run still beats no run.
        //
        // So helper mode has no subscriber by construction, and the hardening steps
        // that run there do not emit: they report what degraded back to this process
        // over a pipe, and `SandboxedCommand` turns it into audit events against
        // this subscriber once the command has been waited on (#95).
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
