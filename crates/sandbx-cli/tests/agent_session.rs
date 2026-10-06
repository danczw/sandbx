//! What `--session` parses to, and what it refuses before any I/O.
//!
//! The refusals are the half worth pinning: an id becomes a path component, so a value
//! clap accepts is a value the store will open. Everything here stops at parsing — what
//! a transcript then holds is `sandbx-session`'s own tests.

use clap::Parser;
use sandbx_cli::{Cli, Command, SessionChoice};

fn agent_run(argv: &[&str]) -> sandbx_cli::AgentRun {
    match Cli::parse_from(argv).command {
        Command::AgentRun(args) => args,
        other => panic!("{other:?} is not agent-run"),
    }
}

fn parse(argv: &[&str]) -> Result<sandbx_cli::AgentRun, clap::Error> {
    match Cli::try_parse_from(argv)?.command {
        Command::AgentRun(args) => Ok(args),
        other => panic!("{other:?} is not agent-run"),
    }
}

#[test]
fn no_flag_touches_no_session() {
    let args = agent_run(&["sandbx", "agent-run", "--", "hello"]);

    assert!(matches!(args.session(), SessionChoice::Off));
}

#[test]
fn a_bare_flag_starts_a_new_one() {
    let args = agent_run(&["sandbx", "agent-run", "--session", "--", "hello"]);

    assert!(matches!(args.session(), SessionChoice::New));
}

#[test]
fn the_id_reaches_the_command_as_given() {
    let args = agent_run(&[
        "sandbx",
        "agent-run",
        "--session",
        "mux5s96i",
        "--",
        "hello",
    ]);

    let SessionChoice::Resume(id) = args.session() else {
        panic!("an id was given and not resumed");
    };
    assert_eq!(id.to_string(), "mux5s96i");
}

/// Refused by clap, so the traversal never reaches a `File::open` at all — the same
/// guarantee `--allow-tool` gets from `tool_name`.
#[test]
fn a_traversing_id_is_refused_at_parse_time() {
    for value in ["../../etc/passwd", "..", ".", "/etc/passwd", "a/b", "UPPER"] {
        let error = parse(&["sandbx", "agent-run", "--session", value, "--", "hi"])
            .expect_err("a traversal was accepted");

        assert!(
            error.to_string().contains(value),
            "the refusal did not name {value}: {error}"
        );
    }
}

/// `--session` after `--` is part of the prompt, not a flag, so a bare one followed by
/// words does not quietly resume a session named after the first word.
#[test]
fn a_session_flag_in_the_prompt_is_prompt_text() {
    let args = agent_run(&["sandbx", "agent-run", "--", "--session", "mux5s96i"]);

    assert!(matches!(args.session(), SessionChoice::Off));
    assert_eq!(args.prompt(), "--session mux5s96i");
}
