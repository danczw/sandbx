//! Reports when it is up, conceals itself when told to, and holds until stdin closes.
//! Test-only.
//!
//! Two stages driven from the parent, because the reader the flag is about is another
//! process: it has to look both before and after this call to pin the refusal on it.

use std::io::{BufRead, Write};

fn main() -> std::process::ExitCode {
    let mut lines = std::io::stdin().lock().lines();

    println!("STARTED");
    if std::io::stdout().flush().is_err() || lines.next().is_none() {
        eprintln!("CONCEALMENT PROBE FAILED: the parent closed the pipe before asking");
        return std::process::ExitCode::FAILURE;
    }

    if let Err(error) = sandbx_core::conceal_process_state() {
        eprintln!("CONCEALMENT PROBE FAILED: {error}");
        return std::process::ExitCode::FAILURE;
    }

    println!("CONCEALED");
    if std::io::stdout().flush().is_err() {
        eprintln!("CONCEALMENT PROBE FAILED: could not report back");
        return std::process::ExitCode::FAILURE;
    }

    // Holds rather than exits: a reaped pid has no procfs entry at all, so exiting here would
    // read back as concealment.
    lines.next();
    std::process::ExitCode::SUCCESS
}
