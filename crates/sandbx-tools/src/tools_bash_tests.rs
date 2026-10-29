use sandbx_core::{HelperRefusal, SandboxError};
use std::io;
use std::time::Duration;

use super::sandbox_error;
use crate::ToolError;

const COMMAND: &str = "ls /tmp";

/// Hard-coded rather than read off `sandbox_error`: read off it, these would assert only
/// that it agrees with itself, and a pin reclassified as a failure would still pass.
const NOT_RETRYABLE: [HelperRefusal; 5] = [
    HelperRefusal::PinMismatch,
    HelperRefusal::PinUnreadable,
    HelperRefusal::PinnedScript,
    HelperRefusal::GrantRedirected,
    HelperRefusal::GrantReplaced,
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

/// The `match` inside is exhaustive, so a fourteenth refusal fails to compile until someone
/// decides which kind of wrong the model is told it is.
#[test]
fn every_refusal_is_a_denial_or_a_sandbox_that_would_not_apply() {
    for refusal in HelperRefusal::ALL {
        let expected_denial = match refusal {
            HelperRefusal::PinMismatch
            | HelperRefusal::PinUnreadable
            | HelperRefusal::PinnedScript => true,
            HelperRefusal::GrantRedirected | HelperRefusal::GrantReplaced => true,
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
fn a_refusal_the_policy_decided_tells_the_model_not_to_retry() {
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
            source: io::Error::other("sample"),
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
            after: Duration::from_secs(1),
        },
    );

    assert!(
        matches!(&error, ToolError::TimedOut { subject, .. } if subject == &format!("run `{COMMAND}`")),
        "a command killed on its deadline did run: {error:?}"
    );
}
