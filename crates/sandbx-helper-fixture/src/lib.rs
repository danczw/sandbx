//! What every part of the enforcement suite needs to start a sandboxed command.
//!
//! A dev-dependency only: nothing links this into a build that ships.
//!
//! The alternative is what this replaces — `sandbx-helper/tests/support/mod.rs`, declared
//! `mod support;` by each of four roots in the same package, which worked. Two things
//! make a crate better. A test root declaring a non-test submodule is what #333 set out
//! to end, the `mod` line being indistinguishable from one naming a test file. And
//! `dead_code` is per test target, so every item had to sit in the intersection all four
//! roots use or warn in the ones that did not: compiled once with a public surface, that
//! constraint is gone and the last paragraph here is what it cost instead.
//!
//! A `#[cfg(feature = ..)]` export from `sandbx-helper` would have kept one package at
//! the price of a surface that diverges between builds — on in the rlib `--all-targets`
//! builds, off in the release build — so production code naming the fixture would pass
//! clippy and the whole suite and fail first at release. `context/guide-ci.md` records
//! that for a *self* dev-dependency; feature unification makes this case the same one.
//!
//! The helper binary is a **parameter** and not an `env!`, which is what made this
//! movable at all: `CARGO_BIN_EXE_sandbx-helper` is set only for a target of the package
//! declaring that bin, so the same `env!` compiled here would resolve nowhere. Each root
//! passes the path its own Cargo run gave it (#328 decision 5, #347).
//!
//! Ungated, and so compiled by the default `cargo test`, `clippy --all-targets` and `doc`
//! runs rather than only behind `sandbox-integration` as the module was. That is a net
//! gain: the fixture is type-checked on every CI job instead of one. It is still
//! Linux-only, not by a `cfg` of its own but because `sandbx-core` refuses to compile
//! anywhere else, and the whole workspace already rests on that.
//!
//! No item here is pinned to the intersection of what the roots share, as the module's
//! were. `dead_code` is per test crate, so an item one root did not use warned there;
//! compiled once with a public surface, that constraint is gone.

use std::path::Path;
use std::process::Command;

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
pub fn run(
    helper: &Path,
    policy: &SandboxPolicy,
    program: &str,
    args: &[&str],
) -> std::process::Output {
    run_pinned(helper, policy, program, args, None)
}

/// [`run`], with the program's bytes named as well.
pub fn run_pinned(
    helper: &Path,
    policy: &SandboxPolicy,
    program: &str,
    args: &[&str],
    pin: Option<sandbx_core::Sha256Digest>,
) -> std::process::Output {
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
