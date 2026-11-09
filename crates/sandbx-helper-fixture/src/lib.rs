//! What the enforcement suite needs to start a sandboxed command, read the trail it left, and
//! ask whether this host can enforce a step at all.
//!
//! A dev-dependency only: nothing links this into a build that ships.
//!
//! A crate, not a `tests/support/mod.rs` each test root declares: that `mod` line is
//! indistinguishable from one naming a test file (#333), and `dead_code` is per test target,
//! so every item would have to be used by all six roots or warn. Nor a
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
use std::sync::{Arc, Mutex};
use std::{fmt, fs};

use sandbx_core::{AUDIT_TARGET, HelperArgs, SandboxPolicy, VettedPath};
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

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

/// Collects the audit trail's events, one `field=value ` line each, for a test to assert on.
#[derive(Clone, Default)]
pub struct Captured(Arc<Mutex<Vec<String>>>);

impl Captured {
    /// Every line recorded so far.
    pub fn lines(&self) -> Vec<String> {
        self.0
            .lock()
            .expect("the sink is held only to copy or push")
            .clone()
    }
}

impl<S: tracing::Subscriber> Layer<S> for Captured {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        if event.metadata().target() != AUDIT_TARGET {
            return;
        }
        let mut visitor = Collect(String::new());
        event.record(&mut visitor);
        self.0
            .lock()
            .expect("the sink is held only to copy or push")
            .push(visitor.0);
    }
}

struct Collect(String);

impl Visit for Collect {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.0.push_str(&format!("{}={value:?} ", field.name()));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.push_str(&format!("{}={value} ", field.name()));
    }
}

/// Can this machine drop the capability bounding set at all? Needs `CAP_SETPCAP`, held
/// only in a self-created user namespace, and not there under AppArmor's
/// `restrict_unprivileged_userns` (Ubuntu 24.04+, GitHub's runners), which lets `unshare`
/// succeed but makes `PR_CAPBSET_DROP` return `EPERM`.
pub fn bounding_set_is_droppable() -> bool {
    use std::os::unix::fs::MetadataExt;

    // The restriction covers *unprivileged* userns only, so root holds `CAP_SETPCAP` in the
    // new namespace regardless. Off `/proc/self`'s owner since `libc::geteuid` is `unsafe`.
    let root = fs::metadata("/proc/self")
        .map(|proc_self| proc_self.uid() == 0)
        .unwrap_or(false);

    root || fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
        .map(|value| value.trim() != "1")
        .unwrap_or(true)
}
