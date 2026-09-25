//! Argument parsing for `sandbx sandbox-run`, and the policy it derives.
//!
//! The policy is the security-relevant half: a flag that silently widens it, or
//! a command argument mistaken for one of sandbx's own flags, is a sandbox escape
//! dressed as a usability bug.

use clap::Parser;
use sandbx_cli::{Cli, Command};

fn sandbox_run(argv: &[&str]) -> sandbx_cli::SandboxRun {
    match Cli::parse_from(argv).command {
        Command::SandboxRun(args) => args,
    }
}

/// The only thing granted without a flag is what any command needs to start.
/// Nothing of the user's is reachable, nothing is writable, no network.
#[test]
fn grants_only_what_a_command_needs_to_start() {
    let policy = sandbox_run(&["sandbx", "sandbox-run", "--", "true"]).policy();

    assert_eq!(
        policy.readable_paths(),
        sandbx_core::SandboxPolicy::default()
            .allow_system_executables()
            .readable_paths(),
        "default read access is wider than the loader and system binaries"
    );
    assert!(policy.writable_paths().is_empty(), "writable by default");
    assert!(!policy.allows_network(), "network on by default");
}

#[test]
fn each_allow_flag_widens_only_its_own_axis() {
    let policy = sandbox_run(&[
        "sandbx",
        "sandbox-run",
        "--allow-read",
        "/srv",
        "--",
        "true",
    ])
    .policy();

    assert!(
        policy
            .readable_paths()
            .contains(&std::path::PathBuf::from("/srv")),
        "the requested path was not granted"
    );
    assert!(policy.writable_paths().is_empty(), "read implied write");
    assert!(!policy.allows_network(), "read implied network");
}

#[test]
fn allow_flags_repeat_to_grant_several_paths() {
    let policy = sandbox_run(&[
        "sandbx",
        "sandbox-run",
        "--allow-read",
        "/a",
        "--allow-read",
        "/b",
        "--allow-write",
        "/c",
        "--",
        "true",
    ])
    .policy();

    for granted in ["/a", "/b"] {
        assert!(
            policy
                .readable_paths()
                .contains(&std::path::PathBuf::from(granted)),
            "{granted} was not granted"
        );
    }
    assert_eq!(policy.writable_paths(), [std::path::PathBuf::from("/c")]);
}

#[test]
fn network_is_opt_in() {
    let policy = sandbox_run(&["sandbx", "sandbox-run", "--allow-network", "--", "true"]).policy();

    assert!(policy.allows_network());
}

#[test]
fn the_command_keeps_its_own_arguments() {
    let args = sandbox_run(&["sandbx", "sandbox-run", "--", "ls", "-la", "/srv"]);

    assert_eq!(args.program(), "ls");
    assert_eq!(args.arguments(), ["-la", "/srv"]);
}

/// The one that matters: past the separator, a flag sandbx also defines belongs
/// to the sandboxed command. Swallowing it here would widen the policy from
/// inside the string sandbx was asked to confine.
#[test]
fn flags_after_the_separator_are_not_our_flags() {
    let args = sandbox_run(&["sandbx", "sandbox-run", "--", "printf", "--allow-network"]);

    assert!(
        !args.policy().allows_network(),
        "command argument widened the policy"
    );
    assert_eq!(args.program(), "printf");
    assert_eq!(args.arguments(), ["--allow-network"]);
}

#[test]
fn a_missing_command_is_rejected() {
    assert!(Cli::try_parse_from(["sandbx", "sandbox-run"]).is_err());
    assert!(Cli::try_parse_from(["sandbx", "sandbox-run", "--allow-network"]).is_err());
}

/// A limit has to survive parsing as the number of seconds given, not some
/// other unit — a timeout silently read as milliseconds would kill every real
/// command.
#[test]
fn timeout_parses_as_seconds() {
    let args = sandbox_run(&["sandbx", "sandbox-run", "--timeout", "5", "--", "true"]);

    assert_eq!(args.timeout(), Some(std::time::Duration::from_secs(5)));
}

/// Absent flag means no limit, matching a plain shell. A default here would
/// start killing long interactive runs nobody asked to bound.
#[test]
fn without_the_flag_there_is_no_timeout() {
    let args = sandbox_run(&["sandbx", "sandbox-run", "--", "true"]);

    assert_eq!(args.timeout(), None);
}

/// Past the separator it belongs to the command, like every other flag.
#[test]
fn a_timeout_after_the_separator_is_not_ours() {
    let args = sandbox_run(&["sandbx", "sandbox-run", "--", "printf", "--timeout", "5"]);

    assert_eq!(args.timeout(), None, "command argument set our own limit");
}

/// #8: the flags are separate axes on the command line too.
#[test]
fn network_does_not_imply_unix_sockets() {
    let policy = sandbox_run(&["sandbx", "sandbox-run", "--allow-network", "--", "true"]).policy();

    assert!(policy.allows_network());
    assert!(!policy.allows_unix_sockets());
}

#[test]
fn unix_sockets_are_opt_in() {
    let granted = sandbox_run(&[
        "sandbx",
        "sandbox-run",
        "--allow-unix-sockets",
        "--",
        "true",
    ])
    .policy();
    let bare = sandbox_run(&["sandbx", "sandbox-run", "--", "true"]).policy();

    assert!(granted.allows_unix_sockets());
    assert!(!bare.allows_unix_sockets());
}
