//! Argument parsing for `sandbx agent-run`, and the policy it derives.
//!
//! The policy half matters for the same reason it does on `sandbox-run`, and more: here
//! the thing choosing which tool to call is a model reading untrusted text, so a flag
//! that silently widens the policy widens what a prompt injection reaches.

use clap::Parser;
use sandbx_cli::{Cli, Command};
use sandbx_core::SandboxPolicy;
use sandbx_tools::{BuiltinTool, RiskLevel};

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

/// The derived default is the part nobody types, and so the part nobody checks. Pinning
/// it across both subcommands is what keeps `Grants` one policy rather than two.
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

/// The default nobody types, and so the one nobody checks: a `write`, an `edit` or a
/// `bash` the model asks for is refused, which is the only thing between a prompt
/// injection and a command running inside the boundary.
#[test]
fn the_read_only_tools_need_no_flag() {
    let args = agent_run(&["sandbx", "agent-run", "--", "hello"]);

    for tool in BuiltinTool::ALL {
        assert_eq!(
            args.approves(tool),
            tool.risk() == RiskLevel::ReadOnly,
            "{tool:?} is approved wrongly with no flag"
        );
    }
}

#[test]
fn a_named_tool_is_the_only_one_lifted() {
    let args = agent_run(&["sandbx", "agent-run", "--allow-tool", "write", "--", "go"]);

    assert!(args.approves(BuiltinTool::Write));
    assert!(!args.approves(BuiltinTool::Edit));
    assert!(!args.approves(BuiltinTool::Bash));
    assert!(args.approves(BuiltinTool::Read), "a read was withdrawn");
}

#[test]
fn a_bare_allow_tool_approves_every_tool() {
    let args = agent_run(&["sandbx", "agent-run", "--allow-tool", "--", "go"]);

    for tool in BuiltinTool::ALL {
        assert!(
            args.approves(tool),
            "{tool:?} is refused under the bare flag"
        );
    }
}

/// The broader spelling yields the narrower set, as `--allow-network` does: the bare
/// flag beside a named one is read as the named one alone.
#[test]
fn mixing_a_bare_flag_with_a_tool_narrows_to_the_tool() {
    let args = agent_run(&[
        "sandbx",
        "agent-run",
        "--allow-tool",
        "--allow-tool",
        "write",
        "--",
        "go",
    ]);

    assert!(args.approves(BuiltinTool::Write));
    assert!(!args.approves(BuiltinTool::Bash));
}

/// An unknown name resolves to no tool, so taking it would approve nothing and exit 0
/// — leaving whoever wrote `--allow-tool shell` believing `bash` would run.
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
