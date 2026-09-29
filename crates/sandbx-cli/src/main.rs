//! The `sandbx` binary: helper dispatch, then the command line.
//!
//! Holds only what needs a real process — the argument parsing and policy
//! derivation it drives live in the library half, where they are testable
//! without a sandbox-capable kernel.

use clap::Parser;
use sandbx_cli::{Cli, Command};

fn main() -> std::process::ExitCode {
    // Must come before argument parsing: `SandboxedCommand` re-execs this same
    // binary as its helper, and in that mode the process restricts itself and
    // becomes the target command.
    if let Some(error) = sandbx_core::dispatch_helper_mode(std::env::args_os()) {
        // The restrictions were not applied, so continuing would run the
        // command unsandboxed.
        eprintln!("sandbx: sandbox helper failed: {error}");
        return std::process::ExitCode::FAILURE;
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
}
