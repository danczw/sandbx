//! The name the binary is installed under.
//!
//! A security test, not a cosmetic one: a name the shell resolves itself does not fail,
//! it succeeds — so a hand check of the sandbox looks like a working run.

use clap::CommandFactory;
use sandbx_cli::Cli;

/// Names a POSIX shell resolves before searching `$PATH`, so installing the binary cannot
/// rescue one that appears here. Not exhaustive, and does not need to be.
const SHELL_BUILTINS: &[&str] = &[
    ".", ":", "alias", "bg", "bind", "break", "builtin", "cd", "command", "continue", "declare",
    "dirs", "disown", "echo", "enable", "eval", "exec", "exit", "export", "false", "fc", "fg",
    "getopts", "hash", "help", "history", "jobs", "kill", "let", "local", "logout", "popd",
    "printf", "pushd", "pwd", "read", "readonly", "return", "set", "shift", "source", "suspend",
    "test", "time", "times", "trap", "true", "type", "typeset", "ulimit", "umask", "unalias",
    "unset", "wait",
];

#[test]
fn the_binary_name_is_not_shadowed_by_a_shell_builtin() {
    let name = Cli::command().get_name().to_string();

    assert!(
        !SHELL_BUILTINS.contains(&name.as_str()),
        "`{name}` is a shell builtin, so `{name} …` never reaches this binary: \
         the shell answers instead, prints the arguments back and exits 0. \
         Installing to $PATH does not help — a builtin is resolved first."
    );
}

#[test]
fn the_binary_is_named_sandbx() {
    assert_eq!(Cli::command().get_name(), "sandbx");
}
