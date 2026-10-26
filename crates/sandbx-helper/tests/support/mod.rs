//! What every part of the enforcement suite needs to start a sandboxed command.
//!
//! The intersection only: `dead_code` is per test crate, so a helper one target does not use
//! warns there and belongs in the file that uses it. The probes beside this file are
//! `[[bin]]` targets, not modules.
// `Command::new` here spawns the sandbox helper itself; the workspace ban exists to stop
// code executing *around* the sandbox.
#![allow(clippy::disallowed_methods)]

use std::path::Path;
use std::process::Command;

use sandbx_core::{HelperArgs, SandboxPolicy, VettedPath};

/// `path`, pinned to the object it names — the shape every grant takes (#212). Resolving is
/// part of the vet, which is what a merged-`/usr` host needs: it spells `/bin` as a symlink,
/// and the helper refuses a grant that opens as something else.
pub(crate) fn vetted(path: impl AsRef<Path>) -> VettedPath {
    VettedPath::vet(path).expect("an existing path to pin the grant to")
}

/// `exec` happens *after* the restrictions are applied, so the interpreter and shared
/// libraries must stay reachable. Program directories need read *and* execute;
/// `ld.so.cache` the loader only reads.
pub(crate) fn runtime_paths(policy: SandboxPolicy) -> SandboxPolicy {
    let policy = ["/usr", "/bin", "/lib", "/lib64"]
        .iter()
        .filter_map(|p| VettedPath::vet(p).ok())
        .fold(policy, SandboxPolicy::allow_read_execute);

    ["/etc/ld.so.cache"]
        .iter()
        .filter_map(|p| VettedPath::vet(p).ok())
        .fold(policy, SandboxPolicy::allow_read)
}

/// Probes live under `target/`, which `runtime_paths` does not cover; without this a denial
/// test passes because nothing ran rather than because the kernel refused.
pub(crate) fn allow_probe(policy: SandboxPolicy, probe: &str) -> SandboxPolicy {
    let dir = Path::new(probe).parent().expect("probe path has a parent");

    policy.allow_read_execute(vetted(dir))
}

pub(crate) fn run(policy: &SandboxPolicy, program: &str, args: &[&str]) -> std::process::Output {
    run_pinned(policy, program, args, None)
}

/// [`run`], with the program's bytes named as well.
pub(crate) fn run_pinned(
    policy: &SandboxPolicy,
    program: &str,
    args: &[&str],
    pin: Option<sandbx_core::Sha256Digest>,
) -> std::process::Output {
    let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    Command::new(env!("CARGO_BIN_EXE_sandbx-helper"))
        .arg(sandbx_core::HELPER_FLAG)
        .args(HelperArgs::encode(policy, program, &owned, pin))
        .output()
        .expect("helper should start")
}
