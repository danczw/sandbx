//! What every part of the enforcement suite needs to start a sandboxed command.
//!
//! The intersection only: `dead_code` is per test crate, so a helper one target does not use
//! warns there, and belongs in the file that uses it. The probes beside this file are
//! `[[bin]]` targets, not modules.
// `Command::new` here spawns the sandbox helper itself, never a command that bypasses it;
// the workspace ban exists to stop code executing *around* the sandbox.
#![allow(clippy::disallowed_methods)]

use std::path::Path;
use std::process::Command;

use sandbx_core::{HelperArgs, SandboxPolicy};

/// Paths the helper itself needs in order to `exec` anything at all: `exec` happens
/// *after* the restrictions are applied, so the interpreter and shared libraries must
/// stay reachable. Program directories need read *and* execute; `ld.so.cache` the
/// loader only reads.
pub(crate) fn runtime_paths(policy: SandboxPolicy) -> SandboxPolicy {
    let policy = ["/usr", "/bin", "/lib", "/lib64"]
        .iter()
        .filter(|p| Path::new(p).exists())
        .fold(policy, |acc, p| acc.allow_read_execute(p));

    ["/etc/ld.so.cache"]
        .iter()
        .filter(|p| Path::new(p).exists())
        .fold(policy, |acc, p| acc.allow_read(p))
}

/// Grant execute on a probe binary: probes live under `target/`, which
/// `runtime_paths` does not cover, and without this a denial test passes because
/// nothing ran rather than because the kernel refused.
pub(crate) fn allow_probe(policy: SandboxPolicy, probe: &str) -> SandboxPolicy {
    let dir = Path::new(probe).parent().expect("probe path has a parent");
    policy.allow_read_execute(dir)
}

pub(crate) fn run(policy: &SandboxPolicy, program: &str, args: &[&str]) -> std::process::Output {
    let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    Command::new(env!("CARGO_BIN_EXE_sandbx-helper"))
        .arg(sandbx_core::HELPER_FLAG)
        .args(HelperArgs::encode(policy, program, &owned))
        .output()
        .expect("helper should start")
}
