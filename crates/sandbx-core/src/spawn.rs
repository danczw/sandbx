//! The one place this crate builds a `std::process::Command`.
//!
//! Every process sandbx starts is born here, and is born with its environment
//! already narrowed to the names the policy carries. A construction-time property
//! rather than a step each caller remembers: the environment is handed over by
//! `fork`/`exec` before Landlock or seccomp have any say, so neither can express
//! "not this" about a variable, and the only way to withhold one is to never put
//! it there (#98).
//!
//! Collapsing the four spawn sites into this one is what makes that falsifiable.
//! While each site cleared for itself every one of them was unobservable — the
//! stages mask each other, so any single clear could be deleted and the command's
//! `environ` came out identical, with no test able to tell. There is now one place
//! it happens, and nothing that reaches `exec` bypasses it.
//!
//! The workspace-wide ban on `Command::new` (`clippy.toml`) therefore has exactly
//! one exception, and it is here. A second would be a process built outside this
//! narrowing, which is the shape of the bug this module exists to make
//! unavailable.

use std::ffi::OsStr;

use crate::SandboxPolicy;

/// Build a command for `program` whose environment holds only what `policy` names.
///
/// Clear and re-add rather than remove what looks sensitive: an allowlist stays
/// correct as the harness gains variables, where a denylist is only ever as current
/// as the last person who thought about it.
///
/// Values are read out of *this* process as the command is built, rather than
/// carried on the policy, because the policy crosses into the helper as argv — and
/// argv is readable from inside the sandbox through `/proc/self/cmdline`, which is
/// exactly the place a value must not be.
///
/// A name the harness does not hold is absent from the child rather than present
/// and empty, which is the difference between "not granted" and "granted, value
/// blank" for a command that branches on whether a variable is set.
pub(crate) fn command(program: impl AsRef<OsStr>, policy: &SandboxPolicy) -> std::process::Command {
    // The one sanctioned `Command::new` in the workspace — see the module docs for
    // why this is the only one, and `clippy.toml` for what it is an exception to.
    #[allow(clippy::disallowed_methods)]
    let mut command = std::process::Command::new(program);

    command.env_clear();
    command.envs(
        policy
            .allowed_env()
            .iter()
            .filter_map(|name| std::env::var_os(name).map(|value| (name.clone(), value))),
    );

    command
}
