//! The grant flags, and the policy they describe.
//!
//! Shared by every subcommand that runs something, so the axis loop, the one widening it
//! applies, and the working-directory default exist once rather than once per subcommand.
//! Deriving that default, and vetting what a flag names, is `root`; the flags themselves and
//! the loop over them are `flags`; `error` is what stops either. Not links: all three are
//! private, and a crate `//!` may not link anything narrower than `pub`.
//!
//! A no-flag `sandbx sandbox-run` grants read and write on the directory it was run from
//! (#109). Execute and environment were already unconditional, so what the default added was
//! the filesystem axes — and with them the guards that make a *default-reachable write grant*
//! safe to ship, which is most of what this crate is.
//!
//! What it does not reach is a toolchain installed under `$HOME`. `cargo test` is the example
//! everyone reaches for and it is the wrong one: with rustup, `cargo` is `~/.cargo/bin/cargo`
//! and needs `--allow-exec` plus read on `~/.cargo/registry` and `~/.rustup`, none of which a
//! working-directory grant covers. The default removes the flags for the *directory*, not for
//! the build, which is why the README's examples run commands from the system paths.
//!
//! The default lives in [`Grants`], which both subcommands flatten, so `sandbox-run` and
//! `agent-run` cannot disagree about it — and it lives here rather than one layer down, where
//! `SandboxPolicy::default` still grants nothing, so an embedder constructing a policy
//! inherits no convenience it did not ask for. Same shape as `allow_standard_env` in
//! `context/decision-policy.md`: the library ships the strict thing, the CLI opts in.
//!
//! **A path flag suppresses the default rather than adding to it.** The alternative was an
//! unconditional default plus a `--no-default-policy` opt-out, and what decides it is the
//! failure mode rather than the ergonomics: under that shape `sandbx agent-run --allow-read
//! /srv` — a deliberately tight hand-written policy — silently gains write over the whole
//! working tree, an explicit statement of intent widened without saying so. Suppression's
//! failure mode is the mirror and is the safe one, the operator getting less than expected
//! and hearing about it immediately as a permission denial naming the path the grant lacked.
//! Narrow and loud beats wide and silent. Going the other way stays available — unconditional
//! plus opt-out is a strict widening of this — so nothing here forecloses it.
//!
//! [`Grants::policy`] is fallible because deriving can now refuse, and the error threads out
//! through both subcommands. `AgentRun` derives the policy *before* building the client, so a
//! refusal costs no round trip and never reads the key. [`PolicyError`] is this crate's and
//! not core's: deriving a policy is the caller's own step, and `SandboxError` must not grow a
//! variant core never produces. `sandbox-run` has its own two-variant `SandboxRunError` for
//! the reason folding every CLI error into one enum was rejected — that would make the
//! provider and turn variants look reachable from `sandbox-run`.
//!
//! The seam is `vetted_root(root, homes, granted, owned)`, pure with all four inputs injected
//! as values, and `named_homes(home) -> Homes` taking the one variable the same way;
//! `current_root` is the thin wrapper that reads the cwd and `$HOME` off the process. Same
//! split as `resolve(lookup)` / `api_key()` in `sandbx-auth`, with values rather than a
//! closure since nothing is called twice. All three stay private with inline tests: making
//! the seam public so an integration test could drive the refusals is the trade
//! `context/guide-testing.md` forbids. What the integration suite gets instead is the
//! end-to-end refusals in `sandbx-cli`'s `tests/cwd_policy.rs`, which spawn the built binary
//! — the guard reads `getcwd` and `HOME` off the real process, and `set_current_dir` is
//! process-global, so under parallel tests one case would decide another's verdict.

mod error;
mod flags;
mod root;

pub use error::PolicyError;
pub use flags::Grants;
