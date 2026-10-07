//! Public contract of the `bash` tool.
//!
//! Unlike the other built-ins, `bash` spawns a process, so the kernel does the
//! confining. These assert the policy reaches it: a tool that dropped the policy
//! would still look like it worked.
#![cfg(all(feature = "sandbox-integration", target_os = "linux"))]

use sandbx_core::SandboxPolicy;
use sandbx_tools::{BuiltinTool, ExecutionContext, ToolError};
use serde_json::json;

fn context(policy: SandboxPolicy) -> ExecutionContext {
    // The test harness does not dispatch helper mode; point at a binary that does.
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

#[test]
fn surfaces_a_non_zero_exit() {
    let ctx = context(SandboxPolicy::default().allow_system_executables());
    let err = BuiltinTool::Bash
        .execute(json!({ "command": "exit 3" }), &ctx)
        .unwrap_err();

    assert!(matches!(err, ToolError::Failed { .. }), "got {err:?}");
    assert!(format!("{err}").contains('3'), "exit code missing: {err}");
    // The other half of the pair below: a command that really ran names itself, and a
    // sandbox that never applied names the sandbox.
    assert!(
        format!("{err}").starts_with("run `exit 3` failed"),
        "a command that ran did not name itself: {err}"
    );
}

/// The reachable refusal without a pin: the shell is unexecutable under this policy, so
/// Landlock denies the `exec` and stage 2 reports `exec_failed` instead of the command
/// exiting 1 — which is what the pair with `surfaces_a_non_zero_exit` tells apart (#185).
#[test]
fn a_sandbox_that_would_not_apply_is_not_a_command_that_failed() {
    let ctx = context(SandboxPolicy::default());
    let err = BuiltinTool::Bash
        .execute(json!({ "command": "echo hello" }), &ctx)
        .unwrap_err();

    assert!(
        format!("{err}").starts_with("sandbox `echo hello` failed"),
        "a sandbox that would not apply read as something else: {err}"
    );
    assert!(
        !format!("{err}").contains("exit 1"),
        "a command that never ran was reported as having exited: {err}"
    );
}

#[test]
fn the_command_is_confined_by_the_policy() {
    let secret_dir = tempfile::tempdir().unwrap();
    let secret = secret_dir.path().join("secret.txt");
    std::fs::write(&secret, b"SECRET-CONTENTS").unwrap();

    // secret_dir is not granted.
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

/// Without this, the test above would pass on a tool that never works at all.
#[test]
fn granted_paths_are_reachable() {
    let dir = tempfile::tempdir().unwrap();
    // Resolved: the helper refuses a grant that opens as something else, and `$TMPDIR` is a
    // symlink on some hosts.
    let root = dir.path().canonicalize().unwrap();
    std::fs::write(root.join("visible.txt"), b"VISIBLE").unwrap();

    let ctx = context(
        SandboxPolicy::default()
            .allow_system_executables()
            .allow_read(&root),
    );
    let out = BuiltinTool::Bash
        .execute(
            json!({ "command": format!("cat {}/visible.txt", root.display()) }),
            &ctx,
        )
        .unwrap();

    assert!(out.content().contains("VISIBLE"), "got: {}", out.content());
}

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

#[test]
fn a_command_that_outruns_the_timeout_says_so() {
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

/// The Messages API rejects an empty `tool_result`, so a silent success — `touch`,
/// `mkdir -p`, `true` — would otherwise kill the turn.
#[test]
fn a_silent_success_is_reported_not_empty() {
    let ctx = context(SandboxPolicy::default().allow_system_executables());
    let out = BuiltinTool::Bash
        .execute(json!({ "command": "true" }), &ctx)
        .unwrap();

    assert!(
        !out.content().trim().is_empty(),
        "silent success returned empty content"
    );
}

/// A default policy names no variables, so `bash` runs with an empty environment:
/// `allow_system_executables()` alone gets a shell with no `PATH` and no `HOME`.
/// `PWD` is filtered out below because the shell sets it from `getcwd` on startup
/// rather than inheriting it.
#[test]
fn a_command_inherits_only_what_the_policy_names() {
    let ctx = context(SandboxPolicy::default().allow_system_executables());
    let out = BuiltinTool::Bash
        // `env` by bare name: with no `PATH`, a shell falls back to its own
        // compiled-in search path, which is why this runs at all.
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

/// Without this, the empty case above would pass on a layer that passes nothing.
#[test]
fn a_granted_variable_reaches_the_command() {
    let ctx = context(
        SandboxPolicy::default()
            .allow_system_executables()
            // Set by cargo: `set_var` is `unsafe` on edition 2024 and `unsafe` is
            // forbidden workspace-wide, so a test cannot plant its own.
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
