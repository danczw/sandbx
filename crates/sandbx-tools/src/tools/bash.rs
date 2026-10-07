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
pub struct BashInput {
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
pub fn execute(input: BashInput, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
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
            ctx.limits().take_bytes(combine(&stdout, &stderr)),
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
            ctx.limits().take_bytes(combine(&stdout, &stderr))
        ),
    })
}

/// Which kind of wrong a sandbox error is, in the one string the model reads.
///
/// The subject carries what the variant cannot: the model gets only `ToolError`'s `Display`,
/// so ``sandbox `x` `` against ``run `x` `` is what separates a sandbox that would not apply
/// from a command that ran and exited non-zero. A pin is policy naming exact bytes and
/// refuses the next attempt identically, so it is a denial; everything else is a `Failed`,
/// `Denied` rendering as "refused by the sandbox policy" and so lying about a malformed argv
/// or a kernel that would not unshare. `context/guide-tools.md` (#185).
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
        // `FsGuard`'s, which no spawn reaches, so an arm for one would assert something false
        // about an unreachable path. A twelfth refusal still has to be classified here.
        // The label stands in when the stderr is gone — a stage killed between the channel
        // write and its own print leaves the record but not the prose, and a bare
        // ``sandbox `x` failed: `` tells the model nothing about what refused.
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
mod tests {
    use sandbx_core::{HelperRefusal, SandboxError};

    use super::*;

    const COMMAND: &str = "ls /tmp";

    /// Hard-coded rather than read off `sandbox_error`: read off it, these would assert only
    /// that it agrees with itself, and a pin reclassified as a failure would still pass.
    const NOT_RETRYABLE: [HelperRefusal; 3] = [
        HelperRefusal::PinMismatch,
        HelperRefusal::PinUnreadable,
        HelperRefusal::PinnedScript,
    ];

    fn refused(refusal: HelperRefusal) -> ToolError {
        sandbox_error(
            COMMAND,
            SandboxError::HelperRefused {
                refusal,
                detail: "what the helper said".to_string(),
            },
        )
    }

    /// The `match` inside is exhaustive, so a twelfth refusal fails to compile until someone
    /// decides which kind of wrong the model is told it is.
    #[test]
    fn every_refusal_is_a_denial_or_a_sandbox_that_would_not_apply() {
        for refusal in HelperRefusal::ALL {
            let expected_denial = match refusal {
                HelperRefusal::PinMismatch
                | HelperRefusal::PinUnreadable
                | HelperRefusal::PinnedScript => true,
                HelperRefusal::BadHelperArgs
                | HelperRefusal::Landlock
                | HelperRefusal::Seccomp
                | HelperRefusal::NamespaceSetupFailed
                | HelperRefusal::ProcessHardening
                | HelperRefusal::InnerStageFailed
                | HelperRefusal::ExecFailed
                | HelperRefusal::Unsupported => false,
            };

            assert_eq!(
                matches!(refused(refusal), ToolError::Denied { .. }),
                expected_denial,
                "{refusal:?} reached the model as the wrong kind of wrong"
            );
            assert_eq!(
                NOT_RETRYABLE.contains(&refusal),
                expected_denial,
                "{refusal:?} and the pins disagree about retrying"
            );
        }
    }

    #[test]
    fn a_pin_refusal_tells_the_model_not_to_retry() {
        for refusal in NOT_RETRYABLE {
            let error = refused(refusal);

            assert!(
                matches!(&error, ToolError::Denied { reason, .. } if reason == "what the helper said"),
                "{refusal:?} lost the helper's reason: {error:?}"
            );
            assert!(
                error
                    .to_string()
                    .starts_with("refused by the sandbox policy"),
                "{refusal:?} did not read as a refusal: {error}"
            );
        }
    }

    #[test]
    fn a_sandbox_that_would_not_apply_names_the_sandbox_and_not_the_command() {
        for refusal in HelperRefusal::ALL
            .into_iter()
            .filter(|r| !NOT_RETRYABLE.contains(r))
        {
            let rendered = refused(refusal).to_string();

            assert!(
                rendered.starts_with(&format!("sandbox `{COMMAND}` failed")),
                "{refusal:?} did not name the sandbox: {rendered}"
            );
            // The distinction the changed subject exists to make: a model cannot read this
            // as the command having run and exited non-zero.
            assert!(
                !rendered.contains("run `"),
                "{refusal:?} still reads as a command that ran: {rendered}"
            );
        }
    }

    /// A stage killed between its channel write and its own print leaves the record without
    /// the prose, and the model would otherwise be told only that something failed.
    #[test]
    fn a_refusal_that_lost_its_stderr_still_names_what_refused() {
        for refusal in HelperRefusal::ALL {
            let error = sandbox_error(
                COMMAND,
                SandboxError::HelperRefused {
                    refusal,
                    detail: String::new(),
                },
            );

            assert!(
                error.to_string().contains(refusal.label()),
                "{refusal:?} reached the model with no reason at all: {error}"
            );
        }
    }

    #[test]
    fn a_sandbox_that_would_not_start_is_not_a_denial() {
        let error = sandbox_error(
            COMMAND,
            SandboxError::SpawnFailed {
                detail: "could not start the sandbox helper",
                source: std::io::Error::other("sample"),
            },
        );

        assert!(
            error
                .to_string()
                .starts_with(&format!("sandbox `{COMMAND}` failed")),
            "a helper that would not spawn did not name the sandbox: {error}"
        );
    }

    #[test]
    fn a_timeout_names_the_command_that_ran() {
        let error = sandbox_error(
            COMMAND,
            SandboxError::TimedOut {
                after: std::time::Duration::from_secs(1),
            },
        );

        assert!(
            matches!(&error, ToolError::TimedOut { subject, .. } if subject == &format!("run `{COMMAND}`")),
            "a command killed on its deadline did run: {error:?}"
        );
    }
}
