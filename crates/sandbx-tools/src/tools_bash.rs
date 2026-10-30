use serde::Deserialize;

use crate::{ExecutionContext, RiskLevel, ToolError, ToolOutput, ToolSpec};

pub(crate) const SPEC: ToolSpec = ToolSpec {
    name: "bash",
    description: "Run a shell command. Use it for what the other tools do not \
                  cover; prefer a dedicated tool wherever one fits.",
    risk: RiskLevel::Executes,
    schema,
    run,
};

fn schema() -> serde_json::Value {
    schemars::schema_for!(BashInput).to_value()
}

fn run(input: serde_json::Value, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    execute(crate::parse(input)?, ctx)
}

/// Arguments for the `bash` tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct BashInput {
    /// Shell command to run.
    pub command: String,
}

/// Run a shell command under the sandbox.
///
/// The only built-in that spawns, so the kernel does the confining:
/// [`ExecutionContext::sandboxed_command`] applies Landlock, a network namespace
/// and a seccomp filter before `exec`. The command string reaches `sh -c` verbatim;
/// running arbitrary commands is the purpose, and the sandbox — not argument
/// parsing — is what bounds the damage.
pub(crate) fn execute(input: BashInput, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    let command = ctx
        .sandboxed_command("/bin/sh")
        .arg("-c")
        .arg(&input.command);

    let output = command
        .output()
        .map_err(|error| sandbox_error(&input.command, error))?;

    // Borrowed: `from_utf8_lossy` copies nothing on the valid-UTF-8 path.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.success() {
        // The command chooses how much it prints: uncapped, `cat` on a large file
        // returns every byte of it.
        return Ok(ToolOutput::new(
            ctx.limits().truncate_bytes(combine(&stdout, &stderr)),
        ));
    }

    // Without the exit code, a failed command looks like one that printed nothing.
    Err(ToolError::Failed {
        subject: format!("run `{}`", input.command),
        detail: format!(
            "exit {}: {}",
            output
                .status
                .code()
                .map_or_else(|| "signal".to_string(), |c| c.to_string()),
            ctx.limits().truncate_bytes(combine(&stdout, &stderr))
        ),
    })
}

/// Which kind of wrong a sandbox error is, in the one string the model reads.
///
/// The subject carries what the variant cannot — the model gets only `ToolError`'s `Display`,
/// so ``sandbox `x` `` against ``run `x` `` is what separates a sandbox that never applied
/// from a command that ran and exited non-zero. `context/guide-tools.md` (#185).
fn sandbox_error(command: &str, error: sandbx_core::SandboxError) -> ToolError {
    use sandbx_core::{HelperRefusal, SandboxError};

    let ran = || format!("run `{command}`");
    let applied = || format!("sandbox `{command}`");

    match error {
        SandboxError::TimedOut { after } => ToolError::TimedOut {
            subject: ran(),
            after,
        },
        // Exhaustive over the refusals and not over `SandboxError`: the rest of that enum is
        // `FsGuard`'s, which no spawn reaches, so an arm for one would claim an unreachable
        // path is handled.
        // The label stands in when the stderr is gone: a stage killed between the channel
        // write and its own print leaves the record but not the prose.
        SandboxError::HelperRefused { refusal, detail } => {
            let detail = match detail.is_empty() {
                true => refusal.label().to_string(),
                false => detail,
            };

            match refusal {
                // Reachable only through `SandboxedCommand::pin_sha256`, which no built-in sets
                // today; kept because the builder is public and the next spawning tool may.
                HelperRefusal::PinMismatch
                | HelperRefusal::PinUnreadable
                | HelperRefusal::PinnedScript => ToolError::Denied {
                    subject: ran(),
                    reason: detail,
                },
                // The policy refusing a grant, not the environment failing to apply one: one
                // substitution must not read as "try again" here and `RootReplaced` in-process.
                HelperRefusal::GrantRedirected | HelperRefusal::GrantReplaced => {
                    ToolError::Denied {
                        subject: ran(),
                        reason: detail,
                    }
                }
                HelperRefusal::BadHelperArgs
                | HelperRefusal::Landlock
                | HelperRefusal::Seccomp
                | HelperRefusal::NamespaceSetupFailed
                | HelperRefusal::ProcessHardening
                | HelperRefusal::InnerStageFailed
                | HelperRefusal::ExecFailed
                | HelperRefusal::Unsupported => ToolError::Failed {
                    subject: applied(),
                    detail,
                },
            }
        }
        // `SpawnFailed` is the only other thing `output` returns, and the sandbox is what
        // would not start.
        error => ToolError::Failed {
            subject: applied(),
            detail: error.to_string(),
        },
    }
}

/// Join both streams, labelling stderr only when there is some.
fn combine(stdout: &str, stderr: &str) -> String {
    match (stdout.trim().is_empty(), stderr.trim().is_empty()) {
        (_, true) => stdout.trim_end().to_string(),
        (true, false) => format!("stderr: {}", stderr.trim_end()),
        (false, false) => format!("{}\nstderr: {}", stdout.trim_end(), stderr.trim_end()),
    }
}

#[cfg(test)]
#[path = "tools_bash_tests.rs"]
mod tests;
