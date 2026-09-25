use clap::Parser;
use sandbx_cli::{Cli, Command};

fn main() -> std::process::ExitCode {
    // First, before anything else runs. This same binary is what
    // `SandboxedCommand` re-execs as its helper: in that mode the process
    // restricts itself and becomes the target command, so it must never reach
    // ordinary argument parsing.
    if let Some(error) = sandbx_core::dispatch_helper_mode(std::env::args_os()) {
        // Helper mode failed, which means the restrictions were not applied.
        // Returning here would run the command unsandboxed.
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
