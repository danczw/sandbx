//! The grant flags, and the policy they describe.
//!
//! Shared by every subcommand that runs something, so the axis loop, the one widening it
//! applies, and the working-directory default exist once. `root` derives that default and
//! vets what a flag names, `grants` holds the flags and the loop, and `policy_error` is what
//! stops either. Not links: all three are private.
//!
//! A no-flag `sandbox-run` or `agent-run` grants read and write on the directory it was run
//! from, and most of this crate is the guards that make a *default-reachable write grant*
//! safe to ship. It grants the directory, not a toolchain under `$HOME`: the README's
//! `cargo test` example is what that costs.
//!
//! The default lives in [`Grants`], which both subcommands flatten, so they cannot disagree
//! about it — and here rather than in core, where `SandboxPolicy::default` still grants
//! nothing, so an embedder inherits no convenience it did not ask for. Same shape as
//! `allow_standard_env` in `context/decision-policy.md`.
//!
//! **A path flag suppresses the default rather than adding to it.** An unconditional default
//! plus a `--no-default-policy` opt-out was rejected for its failure mode: `agent-run
//! --allow-read /srv`, a deliberately tight policy, would silently gain write over the whole
//! working tree. Suppression fails the safe way, the operator getting less than expected and
//! hearing it at once as a permission denial naming the path. The opt-out shape is a strict
//! widening of this, so nothing here forecloses it.
//!
//! [`Grants::policy`] is fallible, and `agent-run` derives it before building the client, so
//! a refusal costs no round trip and never reads the key. [`PolicyError`] is this crate's and
//! not core's: `SandboxError` must not grow a variant core never produces.
//!
//! # The six working directories a no-flag run refuses
//!
//! Public here because `SECURITY.md` cites this list to back a claim, and the list itself is
//! `vetted_root`'s six arms in a private module. In refusal order, each naming the
//! [`PolicyError`] variant it produces:
//!
//! 1. **The filesystem root**, `/`, which has no parent — `FilesystemRoot`.
//! 2. **`$HOME` itself, or any directory holding it** — `HomeDirectory`. One `starts_with` test
//!    covers both, and it is whole-component, so `/home/u/project-tools` is outside
//!    `/home/u/project`.
//! 3. **A directory holding home directories**, `/home` and its kin — `HomeParent`.
//! 4. **A child of one of those while `$HOME` names no usable home** — `UnnamedHome`. Unset,
//!    relative, unresolvable, not a directory, or itself a home parent: arm 2 then has
//!    nothing to compare, and this stands in for it.
//! 5. **A directory reaching a granted system executable path, either direction** —
//!    `SystemExecutables`. Landlock rights cover a subtree, so containment either way is
//!    reachability; both sides are resolved, so a merged-`/usr` host compares `/usr/bin` with
//!    `/usr/bin`. This arm is also what keeps the derived root non-executable, the one way it
//!    could have been executable being to sit under a granted system path.
//! 6. **A directory reaching harness-owned state**, the session directory above all —
//!    `CwdReachesOwned`. The default grants write over the cwd, and inside the session
//!    directory the cwd *is* the history (#173, with no flag).
//!
//! Each refuses outright rather than deriving a narrower root, because a narrower root would
//! be a grant the operator did not state. Arms 2 to 4 are three readings of one question —
//! whether the cwd is somewhere a person keeps their own files — kept apart because each has
//! a different error for the operator to act on.
//!
//! `vetted_root` and `named_homes` take every input as a value, and `current_root` is the thin
//! wrapper reading the cwd and `$HOME` off the process. They stay private with inline tests:
//! a public seam for an integration test is the trade `context/guide-testing.md` forbids.
//! `sandbx-cli`'s `tests/cwd_policy.rs` spawns the built binary instead, since
//! `set_current_dir` is process-global and parallel tests would decide each other's verdict.

mod grants;
mod policy_error;
mod root;

pub use grants::Grants;
pub use policy_error::PolicyError;
