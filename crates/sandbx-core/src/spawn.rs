//! The one place this crate builds a `std::process::Command`.
//!
//! The environment is handed over by `fork`/`exec` before Landlock or seccomp have any
//! say, so neither can express "not this" about a variable and the only way to withhold
//! one is to never put it there: every process is born here with its environment already
//! narrowed to the names the policy carries. Hence the workspace ban on `Command::new`
//! (`clippy.toml`), with exactly one exception, here.

use std::ffi::OsStr;

use crate::SandboxPolicy;

/// Build a command for `program` whose environment holds only what `policy` names.
///
/// Clear and re-add rather than remove what looks sensitive: an allowlist stays correct as
/// the harness gains variables. Values are read out of *this* process as the command is
/// built rather than carried on the policy, which crosses into the helper as argv —
/// readable from inside the sandbox through `/proc/self/cmdline`. A name the harness does
/// not hold is absent from the child rather than present and empty.
pub(crate) fn command(program: impl AsRef<OsStr>, policy: &SandboxPolicy) -> std::process::Command {
    // The one sanctioned `Command::new` in the workspace; see `clippy.toml`.
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
