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

/// The package root, where cargo runs an integration test: neither `$HOME` nor the
/// filesystem root, so the default derives cleanly here.
fn cwd() -> std::path::PathBuf {
    std::env::current_dir()
        .expect("a working directory")
        .canonicalize()
        .expect("an openable working directory")
}

/// The paths of a set of grants. Each also carries the object at its path (#212), derived
/// from the path, so these tests assert over the spelling and the pin follows.
fn spellings(granted: &[sandbx_core::VettedPath]) -> Vec<&std::path::Path> {
    granted.iter().map(sandbx_core::VettedPath::path).collect()
}

/// A scratch root holding `names`, each a real directory, and their absolute spellings.
///
/// A flag's path has to name something now that a grant carries the object at it, so a
/// fixture cannot grant `/srv` and hope. Rooted at the resolved `$TMPDIR` because vetting
/// resolves, and the spellings a test compares against are the ones the policy holds.
fn scratch(names: &[&str]) -> (tempfile::TempDir, Vec<String>) {
    let root = std::env::temp_dir()
        .canonicalize()
        .expect("a resolved temporary directory");
    let dir = tempfile::Builder::new()
        .tempdir_in(root)
        .expect("a temporary directory");

    let made = names
        .iter()
        .map(|name| {
            let path = dir.path().join(name);
            std::fs::create_dir(&path).expect("a directory to grant");
            path.to_str().expect("utf-8").to_owned()
        })
        .collect();

    (dir, made)
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

/// Legitimate here, the child being possibly the thing calling the provider, and pinned so
/// dropping it is a visible choice rather than a silent tightening.
#[test]
fn sandbox_run_still_passes_the_harness_credential() {
    let policy = sandbox_run(&[
        "sandbx",
        "sandbox-run",
        "--allow-env",
        "ANTHROPIC_API_KEY",
        "--",
        "true",
    ])
    .policy()
    .expect("the flags describe a policy");

    assert!(
        policy
            .allowed_env()
            .iter()
            .any(|name| name == "ANTHROPIC_API_KEY"),
        "sandbox-run dropped a variable the operator named"
    );
}

/// A write grant the operator did not type, which is what `grants.rs` guards.
#[test]
fn the_working_directory_is_readable_and_writable() {
    let policy = sandbox_run(&["sandbx", "sandbox-run", "--", "true"])
        .policy()
        .expect("the flags describe a policy");

    assert_eq!(
        spellings(policy.readable_paths()),
        [cwd().as_path()],
        "the default read grant is not the working directory alone"
    );
    assert_eq!(
        spellings(policy.writable_paths()),
        [cwd().as_path()],
        "the default write grant is not the working directory alone"
    );
}

/// What a no-flag run has always done, now said rather than inherited: the derived default
/// grants write over the cwd, so the command starts where it already started (#191).
#[test]
fn a_no_flag_run_starts_in_the_working_directory() {
    let policy = sandbox_run(&["sandbx", "sandbox-run", "--", "true"])
        .policy()
        .expect("the flags describe a policy");

    assert_eq!(policy.working_root(), Some(cwd().as_path()));
}

/// The case #191 is about: with a path flag the cwd is refused, so inheriting it starts the
/// command outside its own sandbox.
#[test]
fn a_path_flag_moves_where_the_command_starts() {
    let work = tempfile::tempdir().expect("a temporary directory");
    // Resolved, because the policy holds what the flag resolves to: `$TMPDIR` may name a
    // symlink, and the start directory is one of the grants.
    let expected = work.path().canonicalize().expect("it exists");
    let root = work.path().to_str().expect("a UTF-8 path");

    let policy = sandbox_run(&[
        "sandbx",
        "sandbox-run",
        "--allow-read",
        "/etc",
        "--allow-write",
        root,
        "--",
        "true",
    ])
    .policy()
    .expect("the flags describe a policy");

    assert_eq!(
        policy.working_root(),
        Some(expected.as_path()),
        "the command would have started outside what the flags granted"
    );
}

/// Not additive: a deliberately tight `--allow-read /srv` would otherwise gain write
/// over the working directory too.
#[test]
fn a_path_flag_replaces_the_working_directory() {
    let (_scratch, granted) = scratch(&["srv"]);

    for flag in ["--allow-read", "--allow-write", "--allow-exec"] {
        let policy = sandbox_run(&["sandbx", "sandbox-run", flag, &granted[0], "--", "true"])
            .policy()
            .expect("the flags describe a policy");

        for axis in sandbx_core::Axis::ALL {
            assert!(
                !spellings(policy.paths(axis)).contains(&cwd().as_path()),
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
        spellings(policy.writable_paths()),
        [cwd().as_path()],
        "a flag naming no path suppressed the working-directory default"
    );
}

/// Landlock rights cover a subtree, so a working directory overlapping a system path
/// would inherit execute from `allow_system_executables` — the root `vetted_root` refuses,
/// and the one case this assertion could not see.
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
    let (_scratch, granted) = scratch(&["srv"]);
    let policy = sandbox_run(&[
        "sandbx",
        "sandbox-run",
        "--allow-read",
        &granted[0],
        "--",
        "true",
    ])
    .policy()
    .expect("the flags describe a policy");

    assert!(
        spellings(policy.readable_paths()).contains(&std::path::Path::new(&granted[0])),
        "the requested path was not granted"
    );
    assert!(policy.writable_paths().is_empty(), "read implied write");
    assert!(!policy.allows_network(), "read implied network");
}

#[test]
fn allow_flags_repeat_to_grant_several_paths() {
    let (_scratch, dirs) = scratch(&["a", "b", "c"]);
    let policy = sandbox_run(&[
        "sandbx",
        "sandbox-run",
        "--allow-read",
        &dirs[0],
        "--allow-read",
        &dirs[1],
        "--allow-write",
        &dirs[2],
        "--",
        "true",
    ])
    .policy()
    .expect("the flags describe a policy");

    for granted in &dirs[..2] {
        assert!(
            spellings(policy.readable_paths()).contains(&std::path::Path::new(granted)),
            "{granted} was not granted"
        );
    }
    assert_eq!(
        spellings(policy.writable_paths()),
        [std::path::Path::new(&dirs[2])]
    );
}

#[test]
fn network_is_opt_in() {
    let policy = sandbox_run(&["sandbx", "sandbox-run", "--allow-network", "--", "true"])
        .policy()
        .expect("the flags describe a policy");

    assert!(policy.allows_network());
}

/// Reading the bare flag as an allowlist of no ports would confine a run the operator
/// opened up.
#[test]
fn a_bare_network_flag_means_every_port() {
    let policy = sandbox_run(&["sandbx", "sandbox-run", "--allow-network", "--", "true"])
        .policy()
        .expect("the flags describe a policy");

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
    .policy()
    .expect("the flags describe a policy");

    assert_eq!(
        *policy.network(),
        sandbx_core::NetworkPolicy::Ports(vec![443, 80])
    );
}

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

/// A bare occurrence contributes no value to append, so the narrower spelling wins —
/// fail-closed, and so acceptable rather than a bug.
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
    .policy()
    .expect("the flags describe a policy");

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

/// Swallowing a flag sandbx also defines would let the command's own arguments widen the
/// policy confining it.
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

/// On the error kind, not `is_err()`: `--allow-network` takes an optional value, so a
/// usage error there would pass this too with the missing-command check gone.
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

/// No limit, like a plain shell: a default would kill long runs nobody asked to bound.
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

/// `--allow-exec` is the only way to run a non-system binary, so a read grant leaking
/// onto the execute axis would silently widen it.
#[test]
fn exec_grants_are_repeatable_and_separate_from_read() {
    let (_scratch, dirs) = scratch(&["one", "two", "data"]);
    let policy = sandbox_run(&[
        "sandbx",
        "sandbox-run",
        "--allow-exec",
        &dirs[0],
        "--allow-exec",
        &dirs[1],
        "--allow-read",
        &dirs[2],
        "--",
        "true",
    ])
    .policy()
    .expect("the flags describe a policy");

    let executable = spellings(policy.executable_paths());

    assert!(executable.contains(&std::path::Path::new(&dirs[0])));
    assert!(executable.contains(&std::path::Path::new(&dirs[1])));
    assert!(
        !executable.contains(&std::path::Path::new(&dirs[2])),
        "a read grant reached the execute axis"
    );
}

#[test]
fn nothing_user_supplied_is_executable_by_default() {
    let (_scratch, granted) = scratch(&["srv"]);
    let policy = sandbox_run(&[
        "sandbx",
        "sandbox-run",
        "--allow-read",
        &granted[0],
        "--",
        "true",
    ])
    .policy()
    .expect("the flags describe a policy");

    for path in spellings(policy.executable_paths()) {
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
/// let a tool write a tree it cannot `cat` back.
#[test]
fn allow_write_also_grants_read_at_the_command_line() {
    let (_scratch, granted) = scratch(&["srv"]);
    let policy = sandbox_run(&[
        "sandbx",
        "sandbox-run",
        "--allow-write",
        &granted[0],
        "--",
        "true",
    ])
    .policy()
    .expect("the flags describe a policy");

    let srv = std::path::Path::new(&granted[0]);
    assert!(
        spellings(policy.writable_paths()).contains(&srv),
        "--allow-write did not grant write"
    );
    assert!(
        spellings(policy.readable_paths()).contains(&srv),
        "--allow-write did not grant read alongside it"
    );
}

/// Stated over the axis table rather than flag by flag, including the CLI's one widening.
#[test]
fn every_path_flag_grants_only_its_own_axis() {
    use sandbx_core::Axis;

    let (_scratch, dirs) = scratch(&["subject"]);
    let granted = std::path::Path::new(&dirs[0]);

    for (flag, axis) in [
        ("--allow-read", Axis::Read),
        ("--allow-write", Axis::Write),
        ("--allow-exec", Axis::ReadExecute),
    ] {
        let policy = sandbox_run(&["sandbx", "sandbox-run", flag, &dirs[0], "--", "true"])
            .policy()
            .expect("the flags describe a policy");

        for other in Axis::ALL {
            // `--allow-write` also grants read; nothing else widens.
            let expected = other == axis || (axis == Axis::Write && other == Axis::Read);

            assert_eq!(
                spellings(policy.paths(other)).contains(&granted),
                expected,
                "{flag} granted {:?} on {other:?}",
                granted.display()
            );
        }
    }
}

/// `PATH` above all: without it a bare name reaches only glibc's `/bin:/usr/bin` fallback.
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

/// `NAME=VALUE` would put the value in helper argv, which the sandboxed command reads
/// back out of its own `/proc/self/cmdline`. Only the name is asserted: clap's refusal
/// echoes the value, which `ps` and the shell history already have.
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

/// Through `parse_from`, so this pins the flag's spelling, which the helper argv seam shares.
#[test]
fn the_resolver_hint_is_opt_in() {
    let hinted = sandbox_run(&["sandbx", "sandbox-run", "--dns-over-tcp", "--", "true"])
        .policy()
        .expect("the flags describe a policy");
    let bare = sandbox_run(&["sandbx", "sandbox-run", "--", "true"])
        .policy()
        .expect("the flags describe a policy");

    assert!(hinted.hints_dns_over_tcp());
    assert!(
        !bare.hints_dns_over_tcp(),
        "the resolver hint arrived without being asked for"
    );
}

/// The audit trail must never report a port the operator did not name.
#[test]
fn the_resolver_hint_allowlists_no_port() {
    let policy = sandbox_run(&["sandbx", "sandbox-run", "--dns-over-tcp", "--", "true"])
        .policy()
        .expect("the flags describe a policy");

    assert!(!policy.allows_network(), "the hint granted IP egress");
    assert_eq!(policy.network(), &sandbx_core::NetworkPolicy::Denied);
}

/// Names no path, so it must not be read as an explicit filesystem policy.
#[test]
fn the_resolver_hint_keeps_the_working_directory() {
    let policy = sandbox_run(&["sandbx", "sandbox-run", "--dns-over-tcp", "--", "true"])
        .policy()
        .expect("the flags describe a policy");

    assert_eq!(spellings(policy.writable_paths()), [cwd().as_path()]);
}

/// Refused rather than resolved: honouring the hint would drop the value the operator
/// asked to pass.
#[test]
fn the_hint_with_its_own_variable_is_refused() {
    let error = sandbox_run(&[
        "sandbx",
        "sandbox-run",
        "--dns-over-tcp",
        "--allow-env",
        "RES_OPTIONS",
        "--",
        "true",
    ])
    .policy()
    .expect_err("two flags claiming one variable");

    assert!(
        matches!(error, sandbx_cli::PolicyError::ImposedVariable { .. }),
        "{error} is not the collision refusal"
    );
    let message = error.to_string();
    assert!(
        message.contains("--dns-over-tcp") && message.contains("--allow-env RES_OPTIONS"),
        "the refusal does not name both flags: {message}"
    );
}

/// The refusal matches the colliding name alone, not every name the hint sits beside.
#[test]
fn another_variable_survives_the_resolver_hint() {
    let policy = sandbox_run(&[
        "sandbx",
        "sandbox-run",
        "--dns-over-tcp",
        "--allow-env",
        "GIT_AUTHOR_NAME",
        "--",
        "true",
    ])
    .policy()
    .expect("the flags describe a policy");

    assert!(
        policy
            .allowed_env()
            .iter()
            .any(|name| name == "GIT_AUTHOR_NAME")
    );
    assert!(policy.hints_dns_over_tcp());
}

/// Through `parse_from`, so this pins the flag's spelling too. Order and count are kept:
/// stage 1 renders one hosts line per name.
#[test]
fn the_name_allowlist_is_opt_in_and_ordered() {
    let bounded = sandbox_run(&[
        "sandbx",
        "sandbox-run",
        "--allow-dns",
        "example.com",
        "--allow-dns",
        "api.example.com",
        "--allow-network",
        "443",
        "--",
        "true",
    ])
    .policy()
    .expect("the flags describe a policy");
    let bare = sandbox_run(&["sandbx", "sandbox-run", "--", "true"])
        .policy()
        .expect("the flags describe a policy");

    assert_eq!(
        bounded.allowed_dns_names(),
        ["example.com".to_string(), "api.example.com".to_string()]
    );
    assert!(bounded.bounds_resolution());
    assert!(
        !bare.bounds_resolution(),
        "a run that named no name is paying for a mount namespace"
    );
}

/// The inversion worth a test of its own: the flag bounds resolution *and* leaves the policy
/// no wider, where every other way to resolve a name needs `--allow-read /etc`.
#[test]
fn the_name_allowlist_grants_no_path_and_keeps_the_working_directory() {
    let policy = sandbox_run(&[
        "sandbx",
        "sandbox-run",
        "--allow-dns",
        "example.com",
        "--allow-network",
        "443",
        "--",
        "true",
    ])
    .policy()
    .expect("the flags describe a policy");

    assert_eq!(
        policy
            .writable_paths()
            .iter()
            .map(|granted| granted.path())
            .collect::<Vec<_>>(),
        [cwd().as_path()]
    );
    assert!(
        !policy
            .readable_paths()
            .iter()
            .any(|granted| granted.path() == std::path::Path::new("/etc")),
        "the flag granted read on /etc, which is what it exists to make unnecessary: {:?}",
        policy.readable_paths()
    );
}

/// Each shape in which a nameserver the command can still reach would answer for every name,
/// leaving the allowlist bounding nothing. Refused rather than narrowed: the claim is only
/// true in the shapes that survive this.
#[test]
fn a_reachable_nameserver_beside_the_allowlist_is_refused() {
    let shapes: [(&[&str], &str); 5] = [
        (&["--dns-over-tcp"], "--dns-over-tcp"),
        (&["--allow-network"], "--allow-network"),
        (&["--allow-network", "53"], "53"),
        (&[], "--allow-network"),
        // nscd answers over a unix socket, which glibc asks before it reads the rendered
        // `nsswitch.conf` — so this one is refused even with the ports named.
        (
            &["--allow-network", "443", "--allow-unix-sockets"],
            "--allow-unix-sockets",
        ),
    ];

    for (flags, named) in shapes {
        let mut argv = vec!["sandbx", "sandbox-run", "--allow-dns", "example.com"];
        argv.extend_from_slice(flags);
        argv.extend_from_slice(&["--", "true"]);

        let error = sandbox_run(&argv)
            .policy()
            .expect_err(&format!("--allow-dns was accepted beside {flags:?}"));

        assert!(
            matches!(
                error,
                sandbx_cli::PolicyError::DnsWithResolverHint
                    | sandbx_cli::PolicyError::DnsWithEveryPort
                    | sandbx_cli::PolicyError::DnsWithNameserverPort
                    | sandbx_cli::PolicyError::DnsWithoutEgress
                    | sandbx_cli::PolicyError::DnsWithUnixSockets
            ),
            "{flags:?} was refused for an unrelated reason: {error}"
        );
        let message = error.to_string();
        assert!(
            message.contains("--allow-dns") && message.contains(named),
            "the refusal of {flags:?} does not name both flags: {message}"
        );
    }
}

/// Every file the resolver binds over, not `resolv.conf` alone — and both spellings of one,
/// since `mount(2)` follows a symlink while the pin does not.
#[test]
fn a_grant_naming_a_file_the_allowlist_replaces_is_refused() {
    for bound in sandbx_core::RESOLVER_FILES {
        let error = sandbox_run(&[
            "sandbx",
            "sandbox-run",
            "--allow-dns",
            "example.com",
            "--allow-network",
            "443",
            "--allow-read",
            bound,
            "--",
            "true",
        ])
        .policy()
        .expect_err(&format!(
            "--allow-read {bound} was accepted beside --allow-dns"
        ));

        assert!(
            matches!(error, sandbx_cli::PolicyError::DnsGrantsBoundFile { .. }),
            "--allow-read {bound} was refused for an unrelated reason: {error}"
        );
        let message = error.to_string();
        assert!(
            message.contains("--allow-dns") && message.contains(bound),
            "the refusal does not name both the flag and the path: {message}"
        );
        assert!(
            message.contains("directory"),
            "the refusal names no way forward, and the directory grant is legal: {message}"
        );
    }
}

/// The grant the flag is for, so this must not be refused along with the names above: binding
/// a file inside `/etc` leaves `/etc`'s own inode alone, and that inode is the grant's pin.
#[test]
fn a_grant_above_the_bind_is_accepted_beside_the_allowlist() {
    let policy = sandbox_run(&[
        "sandbx",
        "sandbox-run",
        "--allow-dns",
        "example.com",
        "--allow-network",
        "443",
        "--allow-read",
        "/etc",
        "--",
        "true",
    ])
    .policy()
    .expect("a grant on the directory the bind lands inside");

    assert!(
        policy
            .readable_paths()
            .iter()
            .any(|granted| granted.path() == std::path::Path::new("/etc")),
        "the directory grant did not survive"
    );
}

/// A port the command connects to is the shape the flag is for, so this must not be refused
/// along with the five above.
#[test]
fn a_port_allowlist_without_53_is_accepted() {
    let policy = sandbox_run(&[
        "sandbx",
        "sandbox-run",
        "--allow-dns",
        "example.com",
        "--allow-network",
        "443",
        "--",
        "true",
    ])
    .policy()
    .expect("a name allowlist beside the ports the command connects to");

    assert_eq!(
        *policy.network(),
        sandbx_core::NetworkPolicy::Ports(vec![443])
    );
}

/// An address reads as a host allowlist, which this is not; the rest would forge a field or a
/// comment in the hosts file stage 1 renders.
#[test]
fn a_value_that_is_no_resolvable_name_is_a_usage_error() {
    for bad in [
        "1.2.3.4",
        "::1",
        "",
        "evil.test #",
        "evil.test\tforged.test",
    ] {
        assert!(
            Cli::try_parse_from(["sandbx", "sandbox-run", "--allow-dns", bad, "--", "true"])
                .is_err(),
            "{bad:?} was accepted as a name to resolve"
        );
    }
}

const DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[test]
fn a_pin_digest_reaches_the_command() {
    let run = sandbox_run(&[
        "sandbx",
        "sandbox-run",
        "--pin-sha256",
        DIGEST,
        "--",
        "/bin/true",
    ]);

    assert_eq!(
        run.pin().expect("one digest").map(|d| d.to_string()),
        Some(DIGEST.to_string())
    );
}

/// A pin grants nothing, so it must not be the flag that replaces the default.
#[test]
fn a_pin_never_suppresses_the_cwd_default() {
    let policy = sandbox_run(&[
        "sandbx",
        "sandbox-run",
        "--pin-sha256",
        DIGEST,
        "--",
        "/bin/true",
    ])
    .policy()
    .expect("the flags describe a policy");

    assert!(
        spellings(policy.writable_paths()).contains(&cwd().as_path()),
        "a pin replaced the working-directory default: {:?}",
        spellings(policy.writable_paths())
    );
}

/// Clap refuses this one, so there is no `SandboxRun` to ask — the parse is the check.
#[test]
fn a_malformed_pin_digest_is_refused() {
    for value in ["", "abc", &DIGEST.to_uppercase()] {
        let parsed = Cli::try_parse_from([
            "sandbx",
            "sandbox-run",
            "--pin-sha256",
            value,
            "--",
            "/bin/true",
        ]);

        assert!(
            parsed.is_err(),
            "{value:?} was accepted as a SHA-256 digest"
        );
    }
}

/// Last-wins would quietly choose one of two images for one program.
#[test]
fn a_second_pin_flag_is_refused() {
    let run = sandbox_run(&[
        "sandbx",
        "sandbox-run",
        "--pin-sha256",
        DIGEST,
        "--pin-sha256",
        DIGEST,
        "--",
        "/bin/true",
    ]);

    assert!(run.pin().is_err(), "two digests were accepted");
}

/// sandbx opens the file itself, so a bare name would hash one file and exec another.
#[test]
fn a_pin_on_a_bare_program_name_is_refused() {
    for program in ["true", "./target/debug/sandbx"] {
        let run = sandbox_run(&[
            "sandbx",
            "sandbox-run",
            "--pin-sha256",
            DIGEST,
            "--",
            program,
        ]);

        let error = run
            .pin()
            .expect_err("a pin on a program that is not an absolute path was accepted");

        assert!(
            error.to_string().contains(program),
            "the refusal did not name the program it rejected: {error}"
        );
    }
}
