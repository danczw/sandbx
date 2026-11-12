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

    // #265's own repro, a value clap will not take, an unknown flag and a missing
    // required argument. Then the two argvs that name no subcommand: clap answers both
    // with the help, on stderr, because neither asked for it.
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

/// A read abandoned on a stop is still parked on its blocking thread, and dropping the
/// runtime waits for every such thread. The process must not (#26).
#[test]
fn the_runtime_does_not_wait_for_a_blocking_task_left_running() {
    let started = std::time::Instant::now();

    let result = super::block_on(async {
        tokio::task::spawn_blocking(|| std::thread::sleep(std::time::Duration::from_secs(3)));
        Ok(0)
    });

    assert!(matches!(result, Ok(0)));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "the runtime waited {:?} for a task nobody awaits",
        started.elapsed()
    );
}
