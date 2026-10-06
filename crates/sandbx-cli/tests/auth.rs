//! What argv `auth` accepts. Which action it then takes is `auth_store`'s question: the
//! action is private, and widening it to suit a test would make it an API.

use clap::Parser;
use sandbx_cli::{Cli, Command};

fn parses(argv: &[&str]) -> bool {
    matches!(
        Cli::try_parse_from(argv).map(|cli| cli.command),
        Ok(Command::Auth(_))
    )
}

#[test]
fn the_three_actions_parse() {
    for action in ["login", "logout", "status"] {
        assert!(parses(&["sandbx", "auth", action]), "auth {action}");
    }
}

/// Otherwise `sandbx auth` would reach `execute` with nothing to do and exit 0, reading as
/// a login that worked.
#[test]
fn auth_alone_is_a_usage_error() {
    assert!(!parses(&["sandbx", "auth"]));
}

#[test]
fn an_unknown_action_is_refused() {
    assert!(!parses(&["sandbx", "auth", "signin"]));
}

/// The key goes in on stdin, so there is no flag that could put it in argv — where
/// `/proc/<pid>/cmdline` would publish it to every process on the host.
#[test]
fn login_takes_no_key_argument() {
    assert!(!parses(&["sandbx", "auth", "login", "sk-ant-secret"]));
    assert!(!parses(&[
        "sandbx",
        "auth",
        "login",
        "--key",
        "sk-ant-secret"
    ]));
}

#[test]
fn auth_takes_none_of_the_policy_flags() {
    assert!(!parses(&[
        "sandbx",
        "auth",
        "status",
        "--allow-read",
        "/srv"
    ]));
}
