//! What every part of the enforcement suite needs to start a sandboxed command.
//!
//! A dev-dependency only: nothing links this into a build that ships.
//!
//! A crate, not a `tests/support/mod.rs` each test root declares: that `mod` line is
//! indistinguishable from one naming a test file (#333), and `dead_code` is per test target,
//! so every item would have to be used by all four roots or warn. Nor a
//! `#[cfg(feature = ..)]` export from `sandbx-helper`: its surface would differ between the
//! `--all-targets` and release builds, so production code naming it would pass clippy and the
//! suite and fail first at release — the case `context/guide-ci.md` records for a *self*
//! dev-dependency, which feature unification makes this one.
//!
//! The helper binary is a parameter and not an `env!`: `CARGO_BIN_EXE_sandbx-helper` is set
//! only for a target of the package declaring that bin, so each root passes its own (#347).
//!
//! Ungated, so every CI job type-checks it, at the price of `missing_docs` on every item.
//! Linux-only because `sandbx-core` refuses to compile anywhere else.

use std::path::Path;
use std::process::{Command, Output};

use sandbx_core::{HelperArgs, SandboxPolicy, VettedPath};

/// `path`, pinned to the object it names — the shape every grant takes (#212). Resolving is
/// part of the vet, which is what a merged-`/usr` host needs: it spells `/bin` as a symlink,
/// and the helper refuses a grant that opens as something else.
pub fn vetted(path: impl AsRef<Path>) -> VettedPath {
    VettedPath::vet(path).expect("an existing path to pin the grant to")
}

/// `exec` happens *after* the restrictions are applied, so the interpreter and shared
/// libraries must stay reachable. Program directories need read *and* execute;
/// `ld.so.cache` the loader only reads.
pub fn runtime_paths(policy: SandboxPolicy) -> SandboxPolicy {
    let policy = ["/usr", "/bin", "/lib", "/lib64"]
        .iter()
        .filter_map(|p| VettedPath::vet(p).ok())
        .fold(policy, SandboxPolicy::allow_read_execute);

    ["/etc/ld.so.cache"]
        .iter()
        .filter_map(|p| VettedPath::vet(p).ok())
        .fold(policy, SandboxPolicy::allow_read)
}

/// Probes live under `target/`, which [`runtime_paths`] does not cover; without this a denial
/// test passes because nothing ran rather than because the kernel refused.
pub fn allow_probe(policy: SandboxPolicy, probe: &str) -> SandboxPolicy {
    let dir = Path::new(probe).parent().expect("probe path has a parent");

    policy.allow_read_execute(vetted(dir))
}

/// Run `program` under `policy` through the helper at `helper`, and hand back what it wrote.
///
/// `helper` is `&Path` rather than `&str` so a policy string cannot be passed by accident.
pub fn run(helper: &Path, policy: &SandboxPolicy, program: &str, args: &[&str]) -> Output {
    run_pinned(helper, policy, program, args, None)
}

/// [`run`], with the program's bytes named as well.
pub fn run_pinned(
    helper: &Path,
    policy: &SandboxPolicy,
    program: &str,
    args: &[&str],
    pin: Option<sandbx_core::Sha256Digest>,
) -> Output {
    let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();

    // The one spawn this crate exists to make: `helper` *is* the sandbox, so there is
    // nothing for `SandboxedCommand` to apply around it.
    #[allow(clippy::disallowed_methods)]
    let mut command = Command::new(helper);

    command
        .arg(sandbx_core::HELPER_FLAG)
        .args(HelperArgs::encode(policy, program, &owned, pin))
        .output()
        .expect("helper should start")
}
