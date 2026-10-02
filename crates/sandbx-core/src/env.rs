//! Narrowing a child's environment to what the policy names.
//!
//! Separate from `policy.rs` because this reads the *live* process environment,
//! which policy data does not: the policy carries names, and the values are
//! whatever this process holds at the moment it spawns something.
//!
//! The environment is handed over by `fork`/`exec` before Landlock or seccomp
//! have any say, so neither can express "not this" about a variable — which is
//! why clearing it is a stage of the spawn rather than a rule in the ruleset
//! (#98).

use crate::SandboxPolicy;

/// Narrow `command`'s environment to the variables `policy` names.
///
/// Clear and re-add rather than remove what looks sensitive: an allowlist stays
/// correct as the harness gains variables, where a denylist is only ever as
/// current as the last person who thought about it.
///
/// Idempotent, and deliberately applied at every stage of the spawn path rather
/// than once at the outermost one. After the first clear the environment already
/// *is* the allowlist, so a later stage re-applying this changes nothing — but a
/// helper invoked directly, without sandbx above it, is then sanitised rather
/// than trusted to have been.
///
/// A name the harness does not hold is absent from the child rather than present
/// and empty, which is the difference between "not granted" and "granted, value
/// blank" for a command that branches on whether a variable is set.
pub(crate) fn restrict(command: &mut std::process::Command, policy: &SandboxPolicy) {
    command.env_clear();
    command.envs(
        policy
            .allowed_env()
            .iter()
            .filter_map(|name| std::env::var_os(name).map(|value| (name.clone(), value))),
    );
}
