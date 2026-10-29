//! Unit tests for the ruleset layer: [`grants`] for what an axis confers, [`rules`] for the
//! one-rule-per-grant mapping, [`net`] for which network states reach Landlock, [`compat`]
//! for the ABI ladder and the enforcement verdict, [`opened`] for which directory a grant
//! turns out to name.
//!
//! All kernel-free — no root, no network namespace, no Landlock-capable host. A live kernel
//! is `sandbx-helper`'s `tests/enforcement.rs` and `tests/enforcement_syscalls.rs`.

#[path = "helper_ruleset_tests_compat.rs"]
mod compat;
#[path = "helper_ruleset_tests_grants.rs"]
mod grants;
#[path = "helper_ruleset_tests_net.rs"]
mod net;
#[path = "helper_ruleset_tests_opened.rs"]
mod opened;
#[path = "helper_ruleset_tests_rules.rs"]
mod rules;

use crate::{SandboxError, SandboxPolicy};
use landlock::AccessFs;

use super::RequestedNet;
use super::compat::{
    BASELINE_ABI, LATEST_ABI, NEGOTIABLE_ABI, enforcement_verdict, negotiated_abi_from,
};
use super::opened::open_grant;
use super::requested::requested_at;
use super::rights::rights_for;
