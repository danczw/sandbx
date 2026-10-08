//! The one place this crate builds a `std::process::Command`.
//!
//! The environment crosses `fork`/`exec` before Landlock or seccomp have any say, so
//! neither can express "not this" about a variable: the only way to withhold one is to
//! never put it there. Hence the ban on `Command::new` in `clippy.toml`.

use std::ffi::OsStr;

use crate::SandboxPolicy;

/// Build a command for `program` whose environment holds only what `policy` permits.
/// Clear and re-add, so the allowlist stays correct as the harness gains variables.
/// Allowlisted values are read out of this process here and never carried on the policy,
/// which crosses into the helper as argv and so is readable from inside the sandbox
/// through `/proc/self/cmdline`; an imposed value rides the policy, being a constant.
pub(crate) fn command(program: impl AsRef<OsStr>, policy: &SandboxPolicy) -> std::process::Command {
    // The only `Command::new` in any crate's `src/`; tests that spawn the binary carry
    // their own allow. See `clippy.toml`.
    #[allow(clippy::disallowed_methods)]
    let mut command = std::process::Command::new(program);

    command.env_clear();
    command.envs(
        policy
            .allowed_env()
            .iter()
            .filter_map(|name| std::env::var_os(name).map(|value| (name.clone(), value))),
    );
    // After the allowlist, so a name carried both ways arrives with the policy's value.
    command.envs(policy.imposed_env().iter().copied());

    command
}
