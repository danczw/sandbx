//! Argument parsing for `sandbx agent-run`, and the policy it derives.
//!
//! The policy half matters for the same reason it does on `sandbox-run`, and more: here
//! the thing choosing which tool to call is a model reading untrusted text, so a flag
//! that silently widens the policy widens what a prompt injection reaches.

use clap::Parser;
use sandbx_cli::{Cli, Command};
use sandbx_core::SandboxPolicy;

fn agent_run(argv: &[&str]) -> sandbx_cli::AgentRun {
    match Cli::parse_from(argv).command {
        Command::AgentRun(args) => args,
        other => panic!("{other:?} is not agent-run"),
    }
}

#[test]
fn grants_only_what_a_tool_needs_to_start() {
    let policy = agent_run(&["sandbx", "agent-run", "--", "hello"])
        .policy()
        .expect("the flags describe a policy");

    assert_eq!(
        policy.executable_paths(),
        SandboxPolicy::default()
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

/// Pinning the derived default across both subcommands keeps `Grants` one policy, not two.
#[test]
fn the_default_matches_what_sandbox_run_derives() {
    let agent = agent_run(&["sandbx", "agent-run", "--", "hello"])
        .policy()
        .expect("the flags describe a policy");
    let sandbox = match Cli::parse_from(["sandbx", "sandbox-run", "--", "true"]).command {
        Command::SandboxRun(args) => args.policy().expect("the flags describe a policy"),
        other => panic!("{other:?} is not sandbox-run"),
    };

    for axis in sandbx_core::Axis::ALL {
        assert_eq!(
            agent.paths(axis),
            sandbox.paths(axis),
            "the two subcommands derive a different default for {axis:?}"
        );
    }
}

#[test]
fn the_policy_matches_what_sandbox_run_derives() {
    let flags = [
        "--allow-read",
        "/usr",
        "--allow-write",
        "/tmp",
        "--allow-exec",
        "/bin",
        "--allow-network",
        "--allow-unix-sockets",
        "--allow-env",
        "CARGO_HOME",
    ];

    let mut agent = vec!["sandbx", "agent-run"];
    agent.extend(flags);
    agent.extend(["--", "hello"]);

    let mut sandbox = vec!["sandbx", "sandbox-run"];
    sandbox.extend(flags);
    sandbox.extend(["--", "true"]);

    let agent = agent_run(&agent)
        .policy()
        .expect("the flags describe a policy");
    let sandbox = match Cli::parse_from(&sandbox).command {
        Command::SandboxRun(args) => args.policy().expect("the flags describe a policy"),
        other => panic!("{other:?} is not sandbox-run"),
    };

    for axis in sandbx_core::Axis::ALL {
        assert_eq!(
            agent.paths(axis),
            sandbox.paths(axis),
            "the two subcommands disagree about {axis:?}"
        );
    }
    assert_eq!(agent.allowed_env(), sandbox.allowed_env());
    // `network()` and not `allows_network()`, which answers the same for an unrestricted
    // grant as for an allowlist of one port.
    assert_eq!(agent.network(), sandbox.network());
    assert_eq!(agent.allows_unix_sockets(), sandbox.allows_unix_sockets());
}

/// Spelled as a literal and never read from `auth::ENV_VAR`: an expectation derived from
/// the constant it checks moves with a mutation and so asserts nothing.
#[test]
fn agent_run_refuses_the_harness_credential() {
    let error = agent_run(&[
        "sandbx",
        "agent-run",
        "--allow-env",
        "ANTHROPIC_API_KEY",
        "--",
        "hello",
    ])
    .policy()
    .expect_err("agent-run derived a policy carrying its own credential");

    assert!(
        matches!(
            error,
            sandbx_cli::PolicyError::HarnessCredential {
                name: "ANTHROPIC_API_KEY"
            }
        ),
        "{error:?} is not the credential refusal"
    );
    let message = error.to_string();
    assert!(
        message.contains("--allow-env") && message.contains("sandbox-run"),
        "{message} does not name the flag refused, or what to write instead"
    );
}

/// The test that says the refusal is an identity and not a pattern: no prefix, no suffix,
/// no case folding. A denylist over credential-looking names is what
/// `context/decision-environment-allowlist.md` rejected.
#[test]
fn the_credential_refusal_matches_one_exact_name() {
    for name in [
        "GH_TOKEN",
        "ANTHROPIC_API_KEY_OLD",
        "MY_ANTHROPIC_API_KEY",
        "anthropic_api_key",
        "ANTHROPIC_API_KE",
    ] {
        let policy = agent_run(&[
            "sandbx",
            "agent-run",
            "--allow-read",
            "/usr",
            "--allow-env",
            name,
            "--",
            "hello",
        ])
        .policy()
        .unwrap_or_else(|error| panic!("{name} was refused as a credential: {error}"));

        assert!(
            policy.allowed_env().iter().any(|named| named == name),
            "{name} derived a policy without it"
        );
    }
}

/// The one way the two subcommands are allowed to differ, pinned beside
/// `the_policy_matches_what_sandbox_run_derives`: a refusal, never a quietly narrower
/// policy. That test does not notice this refusal going away, which is why this exists.
#[test]
fn a_divergence_between_the_run_subcommands_is_a_refusal() {
    let flags = ["--allow-read", "/usr", "--allow-env", "ANTHROPIC_API_KEY"];

    let mut agent = vec!["sandbx", "agent-run"];
    agent.extend(flags);
    agent.extend(["--", "hello"]);

    let mut sandbox = vec!["sandbx", "sandbox-run"];
    sandbox.extend(flags);
    sandbox.extend(["--", "true"]);

    let error = agent_run(&agent)
        .policy()
        .expect_err("agent-run passed its own credential to a tool");
    assert!(
        matches!(
            error,
            sandbx_cli::PolicyError::HarnessCredential {
                name: "ANTHROPIC_API_KEY"
            }
        ),
        "{error:?} is a divergence, but not the refusal this pins"
    );

    let sandbox = match Cli::parse_from(&sandbox).command {
        Command::SandboxRun(args) => args.policy().expect("the flags describe a policy"),
        other => panic!("{other:?} is not sandbox-run"),
    };
    assert!(
        sandbox
            .allowed_env()
            .iter()
            .any(|named| named == "ANTHROPIC_API_KEY"),
        "sandbox-run was narrowed where it should only ever have been refused"
    );
}

/// Decidable from argv alone, so it lands first. Explicit path flags, because without one
/// the cwd default is derived and a test run from a refusable directory would pass for the
/// wrong reason.
#[test]
fn the_refusal_lands_before_the_policy_is_derived() {
    let error = agent_run(&[
        "sandbx",
        "agent-run",
        "--allow-read",
        "/usr",
        "--allow-env",
        "ANTHROPIC_API_KEY",
        "--dns-over-tcp",
        "--allow-env",
        "RES_OPTIONS",
        "--",
        "hello",
    ])
    .policy()
    .expect_err("the credential reached a derived policy");

    assert!(
        matches!(
            error,
            sandbx_cli::PolicyError::HarnessCredential { name: _ }
        ),
        "{error:?} reports something other than the credential, which would mask it"
    );
}

#[test]
fn a_write_grant_confers_read_here_too() {
    let policy = agent_run(&["sandbx", "agent-run", "--allow-write", "/tmp", "--", "go"])
        .policy()
        .expect("the flags describe a policy");

    assert!(
        policy
            .readable_paths()
            .iter()
            .any(|path| path == std::path::Path::new("/tmp")),
        "a tool can rewrite /tmp but not read it back"
    );
}

#[test]
fn the_model_has_a_default_and_takes_an_override() {
    assert_eq!(
        agent_run(&["sandbx", "agent-run", "--", "hello"]).model(),
        "claude-sonnet-5"
    );
    assert_eq!(
        agent_run(&[
            "sandbx",
            "agent-run",
            "--model",
            "claude-opus-5",
            "--",
            "hi"
        ])
        .model(),
        "claude-opus-5"
    );
}

#[test]
fn max_tokens_has_a_default_and_takes_an_override() {
    assert_eq!(
        agent_run(&["sandbx", "agent-run", "--", "hello"]).max_tokens(),
        4096
    );
    assert_eq!(
        agent_run(&["sandbx", "agent-run", "--max-tokens", "64", "--", "hi"]).max_tokens(),
        64
    );
}

#[test]
fn no_system_prompt_is_sent_unless_asked_for() {
    assert_eq!(
        agent_run(&["sandbx", "agent-run", "--", "hello"]).system(),
        None
    );
    assert_eq!(
        agent_run(&["sandbx", "agent-run", "--system", "be terse", "--", "hi"]).system(),
        Some("be terse")
    );
}

#[test]
fn the_prompt_keeps_its_words_in_order() {
    assert_eq!(
        agent_run(&["sandbx", "agent-run", "--", "what", "is", "in", "/srv?"]).prompt(),
        "what is in /srv?"
    );
}

#[test]
fn flags_after_the_separator_are_part_of_the_prompt() {
    let args = agent_run(&[
        "sandbx",
        "agent-run",
        "--",
        "explain",
        "--allow-read",
        "/etc",
    ]);

    assert_eq!(args.prompt(), "explain --allow-read /etc");
    assert!(
        args.policy()
            .expect("the flags describe a policy")
            .readable_paths()
            .iter()
            .all(|path| path != std::path::Path::new("/etc")),
        "a grant written inside the prompt widened the policy"
    );
}

#[test]
fn a_missing_prompt_is_rejected() {
    assert!(Cli::try_parse_from(["sandbx", "agent-run"]).is_err());
    assert!(Cli::try_parse_from(["sandbx", "agent-run", "--allow-read", "/srv"]).is_err());
}

/// An unknown name resolves to no tool, so taking it would approve nothing and exit 0.
#[test]
fn an_unknown_tool_name_is_refused_loudly() {
    let error = Cli::try_parse_from(["sandbx", "agent-run", "--allow-tool", "shell", "--", "go"])
        .expect_err("a name no tool answers to was accepted");

    let message = error.to_string();
    assert!(message.contains("shell"), "got {message}");
    assert!(
        message.contains("bash"),
        "the names were not listed: {message}"
    );
}

#[test]
fn a_variable_name_with_a_value_is_refused_here_too() {
    assert!(
        Cli::try_parse_from([
            "sandbx",
            "agent-run",
            "--allow-env",
            "TOKEN=secret",
            "--",
            "go"
        ])
        .is_err(),
        "a secret written as a name passed nothing, and said nothing"
    );
}
