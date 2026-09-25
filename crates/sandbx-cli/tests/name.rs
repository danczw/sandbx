//! The name the binary is installed under.
//!
//! This is a security test, not a cosmetic one. A command name that a shell
//! resolves to something else does not fail — it succeeds, printing its own
//! arguments and exiting 0. Someone checking the sandbox by hand then sees what
//! looks like a working run while nothing was confined at all, which is the one
//! failure mode a sandbox cannot afford.

use clap::CommandFactory;
use sandbx_cli::Cli;

/// Names a POSIX shell resolves before searching `$PATH`.
///
/// A builtin wins over `$PATH` in bash, zsh, dash and sh, so installing the
/// binary cannot rescue a name that appears here. The list is the POSIX special
/// builtins plus the regular ones bash and zsh provide; it does not need to be
/// exhaustive to catch the mistake it exists to catch.
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

/// Pins the name, so a rename is a deliberate edit to a test rather than a
/// silent change to what users type.
#[test]
fn the_binary_is_named_sandbx() {
    assert_eq!(Cli::command().get_name(), "sandbx");
}
