//! A refused command line end to end: the code the shell sees, and which channel said so.
//!
//! Spawned rather than called, because the code is the claim — `main` maps clap's error to
//! it and nothing a unit test can reach returns an `ExitStatus`.
// `Command::new` here spawns sandbx itself, never a command that bypasses it; the
// workspace ban exists to stop code executing around the sandbox.
#![allow(clippy::disallowed_methods)]

use std::process::Command;

/// What a spawned sandbx reported.
struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Run sandbx with `argv`, with no key in the environment and nothing on stdin.
///
/// `ANTHROPIC_API_KEY` removed so a developer's own key cannot turn a refusal into a turn:
/// every argv here fails to parse, which is strictly before any credential is read.
fn sandbx(argv: &[&str]) -> Run {
    let output = Command::new(env!("CARGO_BIN_EXE_sandbx"))
        .args(argv)
        .env_remove("ANTHROPIC_API_KEY")
        .output()
        .expect("sandbx should start");

    Run {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// #265's own repro: a prompt without the `--` that separates it from the flags.
#[test]
fn a_prompt_without_the_separator_exits_sixty_four() {
    let run = sandbx(&["tui", "--max-rounds", "1", "no-dashdash"]);

    assert_eq!(run.code, Some(64), "{}", run.stderr);
    // On stderr and not stdout: a caller piping the answer must not find the complaint
    // about the argv in it.
    assert!(run.stderr.contains("no-dashdash"), "{}", run.stderr);
    assert!(run.stdout.is_empty(), "{}", run.stdout);
}

/// A missing required argument, which is the other half of "sandbx would not take this".
#[test]
fn a_missing_argument_exits_sixty_four() {
    let run = sandbx(&["hash"]);

    assert_eq!(run.code, Some(64), "{}", run.stderr);
    assert!(!run.stderr.is_empty());
}

/// The collision #265 names: under `auth`, 2 already means "a credential source could not
/// be read", so a usage error must not take it.
#[test]
fn an_unknown_auth_flag_is_not_the_code_an_unreadable_source_takes() {
    let run = sandbx(&["auth", "status", "--nonsense"]);

    assert_eq!(run.code, Some(64), "{}", run.stderr);
    assert_ne!(run.code, Some(2));
}

/// An argv that names no subcommand is a refusal, whichever level it stopped at, and the
/// help clap answers it with is not a help anyone asked for.
///
/// Both codes, because both would read as an answer: 0 from `sandbx auth` is the 0
/// `auth status` spends on a key it found, and 2 is the code a cut round earns. The channel
/// with them, since what separates this from `--help` is that clap wrote it to stderr.
#[test]
fn an_argv_naming_no_subcommand_exits_sixty_four() {
    for argv in [[].as_slice(), &["auth"]] {
        let run = sandbx(argv);

        assert_eq!(run.code, Some(64), "{argv:?}: {}", run.stderr);
        assert!(run.stdout.is_empty(), "{argv:?}: {}", run.stdout);
        assert!(run.stderr.contains("Usage"), "{argv:?}: {}", run.stderr);
    }
}

/// `--help` is not a refusal, and the code it keeps is what a script testing for one reads.
#[test]
fn help_and_version_still_exit_zero_on_stdout() {
    for argv in [["--help"], ["--version"]] {
        let run = sandbx(&argv);

        assert_eq!(run.code, Some(0), "{argv:?}: {}", run.stderr);
        // clap routes these to stdout, which is what makes `sandbx --help | less` work.
        assert!(!run.stdout.is_empty(), "{argv:?}");
    }
}
