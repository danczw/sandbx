//! The `sandbx` binary: helper dispatch, then the command line.
//!
//! Holds only what needs a real process; the parsing and policy derivation it drives
//! live in the library half.

use std::io::Write;

use clap::Parser;
use clap::error::ErrorKind;
use sandbx_cli::{Cli, Command};

/// The exit code for a command line sandbx would not accept.
///
/// `EX_USAGE` from `sysexits.h`. Clear of every code a turn can earn — 0, the 2 a bound
/// cut short takes and the 3 a lost operator takes — and of the `128 + n` a signal takes,
/// because a caller has to tell "sandbx refused your arguments" from "the turn ran and was
/// cut short" without grepping stderr (#265).
const USAGE: u8 = 64;

fn main() -> std::process::ExitCode {
    // Must precede argument parsing: `SandboxedCommand` re-execs this binary as its
    // helper, which restricts itself and becomes the target command instead of falling through.
    sandbx_core::with_helper_dispatch(std::env::args_os(), || {
        // Inside the closure, not above: in helper mode this process becomes the sandboxed
        // command, whose stderr is forwarded verbatim, so a subscriber above would leak into
        // it. Helper mode has none; its hardening reports degradations over a pipe instead.
        if let Err(error) = sandbx_cli::logging::init() {
            eprintln!("sandbx: audit trail unavailable: {error}");
        }

        // `try_parse`, so the code for a refused command line is sandbx's choice rather
        // than clap's 2 — which is the code a cut round earns.
        let command = match Cli::try_parse() {
            Ok(cli) => cli.command,
            Err(error) => {
                // Ignored: clap routes help and version to stdout and a refusal to
                // stderr, and a caller that closed the one it asked for already knows.
                let _ = error.print();
                return std::process::ExitCode::from(usage_code(error.kind()));
            }
        };
        let failure = failure_code(&command);

        // Inside the closure so the flag is sandbx's own, not a sandboxed command's; after
        // parsing so a refusal exits with the subcommand's code, and nothing has spawned yet.
        if let Err(error) = sandbx_core::conceal_process_state() {
            eprintln!("sandbx: {error}");
            return std::process::ExitCode::from(failure);
        }

        match command {
            Command::SandboxRun(args) => report(args.execute(), failure),
            Command::AgentRun(args) => report(block_on(args.execute()), failure),
            Command::Tui(args) => report(block_on(args.execute()), failure),
            Command::Hash(args) => report(args.execute(), failure),
            Command::Auth(args) => report(args.execute(), failure),
        }
    })
}

/// The code a command line clap would not take leaves on.
///
/// A free function so the mapping is a unit test rather than a shape only a spawned
/// process shows. `--help` and `--version` are not refusals — clap reports them as errors
/// so the caller decides where they print — and both keep the 0 they have always had.
///
/// Those two and no more, which is the one line to get wrong here. An argv naming no
/// subcommand is `DisplayHelpOnMissingArgumentOrSubcommand`, which clap prints to *stderr*
/// and exits 2: a refusal that answers with the help, not a help anyone asked for. Taking 0
/// for it would make a bare `sandbx auth` indistinguishable from the 0 `auth status` spends
/// on a key it found, and break the claim `README.md` and `SECURITY.md` both make — that no
/// code of a run is reachable by mistyping a flag.
fn usage_code(kind: ErrorKind) -> u8 {
    match kind {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => 0,
        _ => USAGE,
    }
}

/// The code an `Err` exits with, for the subcommand and for anything refused ahead of it.
///
/// 2 under `auth`, not 1: `auth status` already spends 1 on "no key anywhere", and a script
/// branching on that must not read a refused file as an absent one.
///
/// A usage error never reaches here: there is no subcommand to take the code for, which is
/// why [`USAGE`] is one number and not one per command.
fn failure_code(command: &Command) -> u8 {
    match command {
        Command::Auth(_) => 2,
        Command::SandboxRun(_) | Command::AgentRun(_) | Command::Tui(_) | Command::Hash(_) => 1,
    }
}

/// Turn what a subcommand reported into an exit code, saying why on the way out.
///
/// `failure` is the code an `Err` exits with, which a subcommand reserving 1 for an answer
/// of its own has to move off.
fn report(result: Result<i32, impl std::fmt::Display>, failure: u8) -> std::process::ExitCode {
    match result {
        Ok(code) => std::process::ExitCode::from(u8::try_from(code).unwrap_or(failure)),
        Err(error) => {
            // `writeln!` and not `eprintln!`: under `tui` a hung-up screen leaves stderr
            // the same dead descriptor, where the macro's failed write panics and the
            // process exits 101 instead of the code the run earned (#264). The two
            // `eprintln!`s above keep theirs — they run before any screen exists, so
            // stderr there is the one the operator started the process with, not one
            // sandbx took and lost.
            let _ = writeln!(std::io::stderr(), "sandbx: {error}");
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every way clap can refuse an argv takes one code, and the two it reports as errors
    /// without refusing anything take 0.
    ///
    /// Codes as literals, so renumbering [`USAGE`] under the claim `README.md` and
    /// `SECURITY.md` both make fails here.
    #[test]
    fn a_refused_command_line_exits_sixty_four_and_help_exits_zero() {
        let kind = |argv: &[&str]| {
            Cli::try_parse_from(argv)
                .expect_err("clap took an argv it should have refused")
                .kind()
        };

        // #265's own repro first, then a value clap will not take, an unknown flag and a
        // missing required argument — the four shapes already in tree. Then the two argvs
        // that name no subcommand at all: clap answers both by printing the help, which is
        // why they are easy to read as a help anyone asked for, and prints it to stderr
        // because neither is.
        for argv in [
            ["sandbx", "tui", "--max-rounds", "1", "no-dashdash"].as_slice(),
            &[
                "sandbx",
                "sandbox-run",
                "--allow-network",
                "65536",
                "--",
                "true",
            ],
            &["sandbx", "auth", "status", "--nonsense"],
            &["sandbx", "sandbox-run"],
            &["sandbx"],
            &["sandbx", "auth"],
        ] {
            assert_eq!(usage_code(kind(argv)), 64, "{argv:?}");
        }

        // Only what the caller asked for takes 0.
        for argv in [["sandbx", "--help"].as_slice(), &["sandbx", "--version"]] {
            assert_eq!(usage_code(kind(argv)), 0, "{argv:?}");
        }
    }

    /// Non-vacuity for the test above: an argv sandbx accepts produces no code at all, so
    /// what is asserted there is the refusal and not every call.
    #[test]
    fn an_argv_sandbx_accepts_is_not_a_usage_error() {
        Cli::try_parse_from(["sandbx", "sandbox-run", "--", "true"])
            .expect("a well-formed sandbox-run");
    }
}
