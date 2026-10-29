use super::usage_code;
use clap::Parser;
use sandbx_cli::Cli;

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
