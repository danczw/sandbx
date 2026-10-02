//! Unit tests for the ruleset layer: [`grants`] for what an axis confers, [`rules`] for
//! the one-rule-per-grant mapping, [`compat`] for the ABI ladder and the enforcement
//! verdict.
//!
//! All of them are kernel-free — no root, no network namespace, no Landlock-capable host
//! — so they run anywhere. `tests/enforcement.rs` is where a live kernel is involved.

mod compat;
mod grants;
mod rules;

use crate::{SandboxError, SandboxPolicy};
use landlock::AccessFs;

use super::compat::{
    BASELINE_ABI, LATEST_ABI, NEGOTIABLE_ABI, enforcement_verdict, negotiated_abi_from,
};
use super::requested_at;
use super::rights::rights_for;
