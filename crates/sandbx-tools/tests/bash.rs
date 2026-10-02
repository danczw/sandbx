//! Public contract of the `bash` tool.
//!
//! Unlike the other built-ins, `bash` spawns a process, so the kernel does the
//! confining. These assert the policy reaches it — a tool that quietly dropped
//! the policy would still look like it worked.
#![cfg(all(feature = "sandbox-integration", target_os = "linux"))]

use sandbx_core::SandboxPolicy;
use sandbx_tools::{BuiltinTool, ExecutionContext, ToolError};
use serde_json::json;

fn context(policy: SandboxPolicy) -> ExecutionContext {
    // The test harness does not dispatch helper mode, so point at a binary that
    // does rather than re-executing this one.
    ExecutionContext::new(policy).with_helper(env!("CARGO_BIN_EXE_sandbx-tools-test-helper"))
}

#[test]
fn runs_a_command_and_returns_its_output() {
    let ctx = context(SandboxPolicy::default().allow_system_executables());
    let out = BuiltinTool::Bash
        .execute(json!({ "command": "echo hello" }), &ctx)
        .unwrap();

    assert!(out.content().contains("hello"), "got: {}", out.content());
}

/// A non-zero exit is reported, not swallowed — the model needs to know the
/// command failed.
#[test]
fn surfaces_a_non_zero_exit() {
    let ctx = context(SandboxPolicy::default().allow_system_executables());
    let err = BuiltinTool::Bash
        .execute(json!({ "command": "exit 3" }), &ctx)
        .unwrap_err();

    assert!(matches!(err, ToolError::Failed { .. }), "got {err:?}");
    assert!(format!("{err}").contains('3'), "exit code missing: {err}");
}

#[test]
fn the_command_is_confined_by_the_policy() {
    let secret_dir = tempfile::tempdir().unwrap();
    let secret = secret_dir.path().join("secret.txt");
    std::fs::write(&secret, b"SECRET-CONTENTS").unwrap();

    // secret_dir is deliberately not granted.
    let ctx = context(SandboxPolicy::default().allow_system_executables());
    let result = BuiltinTool::Bash.execute(
        json!({ "command": format!("cat {}", secret.display()) }),
        &ctx,
    );

    let rendered = match &result {
        Ok(out) => out.content().to_string(),
        Err(error) => error.to_string(),
    };
    assert!(
        !rendered.contains("SECRET-CONTENTS"),
        "ungranted file leaked through bash: {rendered}"
    );
}

/// Granted paths stay reachable, or the test above would pass on a tool that
/// simply never works.
#[test]
fn granted_paths_are_reachable() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("visible.txt"), b"VISIBLE").unwrap();

    let ctx = context(
        SandboxPolicy::default()
            .allow_system_executables()
            .allow_read(dir.path()),
    );
    let out = BuiltinTool::Bash
        .execute(
            json!({ "command": format!("cat {}/visible.txt", dir.path().display()) }),
            &ctx,
        )
        .unwrap();

    assert!(out.content().contains("VISIBLE"), "got: {}", out.content());
}

/// `bash` output is bounded too: the command chooses how much it prints.
#[test]
fn output_is_bounded() {
    let ctx = context(SandboxPolicy::default().allow_system_executables())
        .with_limits(sandbx_tools::ToolLimits::default().with_max_bytes(200));

    let out = BuiltinTool::Bash
        .execute(json!({ "command": "seq 1 100000" }), &ctx)
        .unwrap();

    assert!(out.content().contains("truncated"), "unbounded output");
    assert!(
        out.content().len() < 1000,
        "got {} bytes",
        out.content().len()
    );
}

/// A command that never finishes must not wedge the caller, and must be
/// distinguishable from one that genuinely failed — the agent retries those
/// differently.
#[test]
fn a_command_that_outruns_the_timeout_is_reported_as_such() {
    let started = std::time::Instant::now();

    let ctx = context(SandboxPolicy::default().allow_system_executables())
        .with_timeout(std::time::Duration::from_millis(200));
    let result = BuiltinTool::Bash.execute(json!({ "command": "sleep 30" }), &ctx);

    let elapsed = started.elapsed();

    assert!(
        matches!(result, Err(ToolError::TimedOut { .. })),
        "expected a timeout, got: {result:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "the tool call stayed blocked for {elapsed:?}"
    );
}

/// The default exists so a caller that never thinks about it is still protected.
#[test]
fn the_default_timeout_is_applied_without_being_asked_for() {
    let ctx = context(SandboxPolicy::default().allow_system_executables());

    assert_eq!(ctx.timeout(), sandbx_tools::DEFAULT_TIMEOUT);
}

/// A command that succeeds silently is the common case — `touch`, `mkdir -p`,
/// `true` — and its result still has to be non-empty, since the Messages API
/// rejects an empty `tool_result` and the turn dies with it.
#[test]
fn reports_a_silent_success_rather_than_returning_nothing() {
    let ctx = context(SandboxPolicy::default().allow_system_executables());
    let out = BuiltinTool::Bash
        .execute(json!({ "command": "true" }), &ctx)
        .unwrap();

    assert!(
        !out.content().trim().is_empty(),
        "silent success returned empty content"
    );
}

/// The environment is part of the policy here too, and a default policy names
/// nothing — so `bash` runs with an empty one (#98).
///
/// Worth pinning at this layer rather than only in `sandbx-core`, because this is
/// the layer where it surprises: `ExecutionContext::new` takes the policy as
/// given and adds nothing, so a harness that grants
/// `allow_system_executables()` alone gets a shell with no `PATH` and no `HOME`.
/// That is the intended default-deny answer, not an oversight, and the test says
/// so where someone reading `context.rs` will find it.
///
/// `PWD` is the one name that still appears, and it is not an inherited one: the
/// shell sets it from `getcwd` on startup, which `env -i /bin/sh -c env` shows
/// outside any sandbox. It is allowed through as a shell's own doing rather than a
/// gap in the policy — the working directory is readable with `getcwd` regardless,
/// so nothing crosses here that the command did not already have.
#[test]
fn a_command_inherits_only_what_the_policy_names() {
    let ctx = context(SandboxPolicy::default().allow_system_executables());
    let out = BuiltinTool::Bash
        // `env` by bare name: a shell falls back to its own compiled-in search
        // path even with no `PATH`, which is why this still runs at all.
        .execute(json!({ "command": "env" }), &ctx)
        .unwrap();

    let inherited: Vec<&str> = out
        .content()
        .lines()
        .filter_map(|line| line.split_once('=').map(|(name, _)| name))
        .filter(|name| *name != "PWD")
        .collect();

    assert!(
        inherited.is_empty(),
        "the command saw {inherited:?}, which the policy never granted: {}",
        out.content()
    );
}

/// And the other half: a named variable arrives, so the empty case above is
/// default-deny rather than the tools layer failing to pass anything at all.
#[test]
fn a_granted_variable_reaches_the_command() {
    let ctx = context(
        SandboxPolicy::default()
            .allow_system_executables()
            // Set by cargo in this test process. `std::env::set_var` is `unsafe`
            // on edition 2024 and `unsafe` is forbidden workspace-wide, so a test
            // cannot plant one of its own.
            .allow_env("CARGO_MANIFEST_DIR"),
    );
    let out = BuiltinTool::Bash
        .execute(json!({ "command": "echo \"$CARGO_MANIFEST_DIR\"" }), &ctx)
        .unwrap();

    assert!(
        out.content().contains(env!("CARGO_MANIFEST_DIR")),
        "a granted variable did not reach the command: {}",
        out.content()
    );
}
