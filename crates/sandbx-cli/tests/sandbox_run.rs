//! Argument parsing for `sandbx sandbox-run`, and the policy it derives.
//!
//! The policy is the security-relevant half: a flag that silently widens it, or a
//! command argument mistaken for one of sandbx's own, is a sandbox escape.

use clap::Parser;
use sandbx_cli::{Cli, Command};

fn sandbox_run(argv: &[&str]) -> sandbx_cli::SandboxRun {
    match Cli::parse_from(argv).command {
        Command::SandboxRun(args) => args,
        other => panic!("{other:?} is not sandbox-run"),
    }
}

/// Where cargo runs an integration test: the package root, which is neither `$HOME` nor
/// the filesystem root and holds no `sandbx` binary, so the default derives cleanly here.
fn cwd() -> std::path::PathBuf {
    std::env::current_dir()
        .expect("a working directory")
        .canonicalize()
        .expect("an openable working directory")
}

#[test]
fn grants_only_what_a_command_needs_to_start() {
    let policy = sandbox_run(&["sandbx", "sandbox-run", "--", "true"])
        .policy()
        .expect("the flags describe a policy");

    assert_eq!(
        policy.executable_paths(),
        sandbx_core::SandboxPolicy::default()
            .allow_system_executables()
            .executable_paths(),
        "default execute access is wider than the loader and system binaries"
    );
    assert!(!policy.allows_network(), "network on by default");
    assert!(
        !policy.allows_unix_sockets(),
        "unix sockets open by default"
    );
}

/// The point of the default: the common case costs no flags. It is a *write* grant the
/// operator did not type, so the guards in `grants.rs` are what keep it narrow.
#[test]
fn the_working_directory_is_readable_and_writable() {
    let policy = sandbox_run(&["sandbx", "sandbox-run", "--", "true"])
        .policy()
        .expect("the flags describe a policy");

    assert_eq!(
        policy.readable_paths(),
        [cwd()],
        "the default read grant is not the working directory alone"
    );
    assert_eq!(
        policy.writable_paths(),
        [cwd()],
        "the default write grant is not the working directory alone"
    );
}

/// A path flag *replaces* the default rather than adding to it. The other way round, a
/// deliberately tight `--allow-read /srv` would silently gain write over the whole tree.
#[test]
fn a_path_flag_replaces_the_working_directory() {
    for flag in ["--allow-read", "--allow-write", "--allow-exec"] {
        let policy = sandbox_run(&["sandbx", "sandbox-run", flag, "/srv", "--", "true"])
            .policy()
            .expect("the flags describe a policy");

        for axis in sandbx_core::Axis::ALL {
            assert!(
                !policy.paths(axis).contains(&cwd()),
                "{flag} left the working directory on the {axis:?} axis"
            );
        }
    }
}

/// `--allow-env` names no path, so it must not be read as an explicit policy.
#[test]
fn an_env_flag_keeps_the_working_directory() {
    let policy = sandbox_run(&["sandbx", "sandbox-run", "--allow-env", "ONE", "--", "true"])
        .policy()
        .expect("the flags describe a policy");

    assert_eq!(
        policy.writable_paths(),
        [cwd()],
        "a flag naming no path suppressed the working-directory default"
    );
}

/// The default adds no execute grant of its own. It cannot promise more than that: Landlock
/// rights cover a subtree, so a working directory *under* a system path — `/usr/src/app`,
/// the stock `WORKDIR` in the official Node images — is executable by way of
/// `allow_system_executables`, and no CLI-level assertion can see that.
#[test]
fn the_default_root_is_not_executable() {
    let bare = sandbox_run(&["sandbx", "sandbox-run", "--", "true"])
        .policy()
        .expect("the flags describe a policy");
    let system = sandbx_core::SandboxPolicy::default().allow_system_executables();

    assert_eq!(
        bare.executable_paths(),
        system.executable_paths(),
        "the default widened the execute axis beyond the system paths"
    );
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
    .policy()
    .expect("the flags describe a policy");

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
    .policy()
    .expect("the flags describe a policy");

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
    let policy = sandbox_run(&["sandbx", "sandbox-run", "--allow-network", "--", "true"])
        .policy()
        .expect("the flags describe a policy");

    assert!(policy.allows_network());
}

/// The bare flag has to keep meaning every port: it is what it meant before ports existed,
/// and reading it as an allowlist of none would confine a run the operator opened up.
#[test]
fn a_bare_network_flag_means_every_port() {
    let policy = sandbox_run(&["sandbx", "sandbox-run", "--allow-network", "--", "true"]).policy();

    assert_eq!(*policy.network(), sandbx_core::NetworkPolicy::AnyPort);
}

#[test]
fn repeated_network_flags_collect_ports() {
    let policy = sandbox_run(&[
        "sandbx",
        "sandbox-run",
        "--allow-network",
        "443",
        "--allow-network",
        "80",
        "--",
        "true",
    ])
    .policy();

    assert_eq!(
        *policy.network(),
        sandbx_core::NetworkPolicy::Ports(vec![443, 80])
    );
}

/// The CLI refuses loudly where the library skips quietly, the same split `--allow-env`
/// makes: a typo that silently granted nothing would leave whoever typed it believing the
/// port had been allowlisted.
///
/// `65536` is the one that distinguishes a real range check from an `as` cast, which would
/// truncate it to the port 0 beside it in the list.
#[test]
fn a_port_outside_the_range_is_a_usage_error() {
    for port in ["0", "65536", "https", "443.0"] {
        let error = Cli::try_parse_from([
            "sandbx",
            "sandbox-run",
            "--allow-network",
            port,
            "--",
            "true",
        ])
        .expect_err("a bad port was accepted");

        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::ValueValidation,
            "{port} was refused for the wrong reason: {error}"
        );
    }

    // A leading dash never reaches the value parser — clap reads it as a flag — so this
    // one is refused a rung earlier. Still a refusal, which is the property that matters.
    let error = Cli::try_parse_from([
        "sandbx",
        "sandbox-run",
        "--allow-network",
        "-1",
        "--",
        "true",
    ])
    .expect_err("a negative port was accepted");
    assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
}

/// A bare occurrence contributes no value to append, so the narrower spelling wins.
/// Fail-closed, which is why it is acceptable rather than a bug.
#[test]
fn mixing_a_bare_flag_with_a_port_narrows_to_the_port() {
    let policy = sandbox_run(&[
        "sandbx",
        "sandbox-run",
        "--allow-network",
        "--allow-network",
        "443",
        "--",
        "true",
    ])
    .policy();

    assert_eq!(
        *policy.network(),
        sandbx_core::NetworkPolicy::Ports(vec![443]),
        "a bare flag mixed with a port widened the policy past what every \
         occurrence of it asked for"
    );
}

#[test]
fn the_command_keeps_its_own_arguments() {
    let args = sandbox_run(&["sandbx", "sandbox-run", "--", "ls", "-la", "/srv"]);

    assert_eq!(args.program(), "ls");
    assert_eq!(args.arguments(), ["-la", "/srv"]);
}

/// Swallowing a flag sandbx also defines would let the sandboxed command's arguments
/// widen the policy meant to confine it.
#[test]
fn flags_after_the_separator_are_not_our_flags() {
    let args = sandbox_run(&["sandbx", "sandbox-run", "--", "printf", "--allow-network"]);

    assert!(
        !args
            .policy()
            .expect("the flags describe a policy")
            .allows_network(),
        "command argument widened the policy"
    );
    assert_eq!(args.program(), "printf");
    assert_eq!(args.arguments(), ["--allow-network"]);
}

/// Matched on the error *kind*, not on `is_err()`: `--allow-network` takes an optional
/// value, so a usage error there would also make this pass while the missing-command check
/// itself had gone.
#[test]
fn a_missing_command_is_rejected() {
    for argv in [
        vec!["sandbx", "sandbox-run"],
        vec!["sandbx", "sandbox-run", "--allow-network"],
        vec!["sandbx", "sandbox-run", "--allow-network", "443"],
    ] {
        let error = Cli::try_parse_from(&argv).expect_err("a command was not required");

        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument,
            "{argv:?} was refused for something other than the missing command: {error}"
        );
    }
}

#[test]
fn timeout_parses_as_seconds() {
    let args = sandbox_run(&["sandbx", "sandbox-run", "--timeout", "5", "--", "true"]);

    assert_eq!(args.timeout(), Some(std::time::Duration::from_secs(5)));
}

/// No limit, matching a plain shell: a default would kill long interactive runs nobody
/// asked to bound.
#[test]
fn without_the_flag_there_is_no_timeout() {
    let args = sandbox_run(&["sandbx", "sandbox-run", "--", "true"]);

    assert_eq!(args.timeout(), None);
}

#[test]
fn a_timeout_after_the_separator_is_not_ours() {
    let args = sandbox_run(&["sandbx", "sandbox-run", "--", "printf", "--timeout", "5"]);

    assert_eq!(args.timeout(), None, "command argument set our own limit");
}

#[test]
fn network_does_not_imply_unix_sockets() {
    let policy = sandbox_run(&["sandbx", "sandbox-run", "--allow-network", "--", "true"])
        .policy()
        .expect("the flags describe a policy");

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
    .policy()
    .expect("the flags describe a policy");
    let bare = sandbox_run(&["sandbx", "sandbox-run", "--", "true"])
        .policy()
        .expect("the flags describe a policy");

    assert!(granted.allows_unix_sockets());
    assert!(!bare.allows_unix_sockets());
}

/// `--allow-exec` is the only way to run a binary that is not a system one, so a read
/// grant leaking onto the execute axis would silently widen it.
#[test]
fn exec_grants_are_repeatable_and_separate_from_read() {
    let policy = sandbox_run(&[
        "sandbx",
        "sandbox-run",
        "--allow-exec",
        "/opt/one",
        "--allow-exec",
        "/opt/two",
        "--allow-read",
        "/srv/data",
        "--",
        "true",
    ])
    .policy()
    .expect("the flags describe a policy");

    assert!(
        policy
            .executable_paths()
            .contains(&std::path::PathBuf::from("/opt/one"))
    );
    assert!(
        policy
            .executable_paths()
            .contains(&std::path::PathBuf::from("/opt/two"))
    );
    assert!(
        !policy
            .executable_paths()
            .contains(&std::path::PathBuf::from("/srv/data")),
        "a read grant reached the execute axis"
    );
}

#[test]
fn nothing_user_supplied_is_executable_by_default() {
    let policy = sandbox_run(&[
        "sandbx",
        "sandbox-run",
        "--allow-read",
        "/srv",
        "--",
        "true",
    ])
    .policy()
    .expect("the flags describe a policy");

    for path in policy.executable_paths() {
        assert!(
            path.starts_with("/usr")
                || path.starts_with("/bin")
                || path.starts_with("/lib")
                || path.starts_with("/lib64"),
            "{} is executable without being granted",
            path.display()
        );
    }
}

/// The library keeps the two axes separate so a caller can build a write-only drop
/// directory; at the command line that is a trap, since `--allow-write ~/project` would
/// let a tool write a tree it cannot `cat` back. The narrow form stays on the API.
#[test]
fn allow_write_also_grants_read_at_the_command_line() {
    let policy = sandbox_run(&[
        "sandbx",
        "sandbox-run",
        "--allow-write",
        "/srv",
        "--",
        "true",
    ])
    .policy()
    .expect("the flags describe a policy");

    let srv = std::path::PathBuf::from("/srv");
    assert!(
        policy.writable_paths().contains(&srv),
        "--allow-write did not grant write"
    );
    assert!(
        policy.readable_paths().contains(&srv),
        "--allow-write did not grant read alongside it"
    );
}

/// Stated over the axis table rather than flag by flag, including the CLI's one
/// widening.
#[test]
fn every_path_flag_grants_only_its_own_axis() {
    use sandbx_core::Axis;

    let granted = std::path::PathBuf::from("/srv/subject");

    for (flag, axis) in [
        ("--allow-read", Axis::Read),
        ("--allow-write", Axis::Write),
        ("--allow-exec", Axis::ReadExecute),
    ] {
        let policy = sandbox_run(&["sandbx", "sandbox-run", flag, "/srv/subject", "--", "true"])
            .policy()
            .expect("the flags describe a policy");

        for other in Axis::ALL {
            // `--allow-write` also grants read; nothing else widens.
            let expected = other == axis || (axis == Axis::Write && other == Axis::Read);

            assert_eq!(
                policy.paths(other).contains(&granted),
                expected,
                "{flag} granted {:?} on {other:?}",
                granted.display()
            );
        }
    }
}

/// `PATH` above all: without it a bare program name reaches only the C library's
/// fallback search path, so anything outside `/bin` and `/usr/bin` is not found.
#[test]
fn the_startup_environment_is_granted_anyway() {
    let policy = sandbox_run(&["sandbx", "sandbox-run", "--", "true"])
        .policy()
        .expect("the flags describe a policy");

    assert_eq!(
        policy.allowed_env(),
        sandbx_core::SandboxPolicy::default()
            .allow_standard_env()
            .allowed_env(),
        "default environment access is wider than what a command needs to start"
    );
}

#[test]
fn passing_a_variable_is_opt_in() {
    let granted = sandbox_run(&[
        "sandbx",
        "sandbox-run",
        "--allow-env",
        "GIT_AUTHOR_NAME",
        "--",
        "true",
    ])
    .policy()
    .expect("the flags describe a policy");
    let bare = sandbox_run(&["sandbx", "sandbox-run", "--", "true"])
        .policy()
        .expect("the flags describe a policy");

    assert!(
        granted
            .allowed_env()
            .iter()
            .any(|name| name == "GIT_AUTHOR_NAME")
    );
    assert!(
        !bare
            .allowed_env()
            .iter()
            .any(|name| name == "GIT_AUTHOR_NAME"),
        "a variable arrived without being asked for"
    );
}

#[test]
fn allow_env_is_repeatable_and_widens_nothing_else() {
    let policy = sandbox_run(&[
        "sandbx",
        "sandbox-run",
        "--allow-env",
        "ONE",
        "--allow-env",
        "TWO",
        "--",
        "true",
    ])
    .policy()
    .expect("the flags describe a policy");

    for name in ["ONE", "TWO"] {
        assert!(
            policy.allowed_env().iter().any(|seen| seen == name),
            "{name} was not granted"
        );
    }
    // Against the bare policy rather than against emptiness: the working-directory
    // default means "widens nothing else" is no longer the same claim as "grants nothing".
    let bare = sandbox_run(&["sandbx", "sandbox-run", "--", "true"])
        .policy()
        .expect("the flags describe a policy");
    for axis in sandbx_core::Axis::ALL {
        assert_eq!(
            policy.paths(axis),
            bare.paths(axis),
            "an env grant widened the {axis:?} axis"
        );
    }
    assert!(!policy.allows_network(), "env implied network");
    assert!(!policy.allows_unix_sockets(), "env implied unix sockets");
}

/// The flag names a variable; it does not set one — `NAME=VALUE` would put the value in
/// helper argv, which the sandboxed command reads back out of its own
/// `/proc/self/cmdline`.
///
/// Refused rather than dropped: `SandboxPolicy::allow_env` skips a name it cannot
/// encode, which would leave `--allow-env TOKEN=hunter2` exiting 0 having passed
/// nothing, and the person who typed it believing the secret crossed. Only the *name*
/// is asserted; clap's refusal echoes the value, which `ps` and the shell history
/// already have.
#[test]
fn a_name_with_a_value_is_refused_rather_than_dropped() {
    let refusal = Cli::try_parse_from([
        "sandbx",
        "sandbox-run",
        "--allow-env",
        "TOKEN=hunter2",
        "--",
        "true",
    ])
    .expect_err("`TOKEN=hunter2` was accepted as a variable name");
    let message = refusal.to_string();

    assert!(
        message.contains("--allow-env TOKEN"),
        "the refusal does not say what to write instead: {message}"
    );
}

/// An empty name matches nothing, and a NUL cannot cross `exec`.
#[test]
fn a_name_that_could_never_match_is_refused() {
    for bad in ["", "FOO\0BAR"] {
        assert!(
            Cli::try_parse_from(["sandbx", "sandbox-run", "--allow-env", bad, "--", "true"])
                .is_err(),
            "{bad:?} was accepted as a variable name"
        );
    }
}
