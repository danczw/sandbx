//! Unit tests for the ruleset layer: [`grants`] for what an axis confers,
//! [`rules`] for the one-rule-per-grant mapping, [`compat`] for the ABI ladder
//! and the enforcement verdict.
//!
//! All of them are deliberately kernel-free — no root, no network namespace, no
//! Landlock-capable host (#52) — so they run anywhere. `tests/enforcement.rs` is
//! where the live kernel is involved.

mod compat;
mod grants;
mod rules;

use crate::SandboxPolicy;
use landlock::AccessFs;

use super::compat::{LATEST_ABI, NEGOTIABLE_ABI, enforcement_verdict};
use super::rights::{fs_rules, rights_for};
