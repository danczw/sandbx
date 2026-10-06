//! `sandbox-run`: one command, under the boundary, and what it did.

use std::io::Write;

use sandbx_core::{NetworkPolicy, SandboxPolicy, SandboxedCommand};

use crate::{Grants, PolicyError, SandboxRunError};

/// What a run that failed under a port allowlist most likely needed, if anything.
///
/// Keyed to a failure and not to the policy alone, because sandbx cannot see the command's
/// own `getaddrinfo` — so this fires for any failure under a port list, resolution or not.
fn resolver_advice(policy: &SandboxPolicy, code: i32) -> Option<&'static str> {
    let narrowed = matches!(policy.network(), NetworkPolicy::Ports(_));
    match narrowed && !policy.hints_dns_over_tcp() && code != 0 {
        true => Some(
            "a port allowlist denies UDP, so names do not resolve. If that was the failure, \
             add --dns-over-tcp --allow-network 53 --allow-read /etc",
        ),
        false => None,
    }
}

/// `sandbx sandbox-run [--allow-…] -- <command> [args…]`
#[derive(Debug, clap::Args)]
pub struct SandboxRun {
    #[command(flatten)]
    grants: Grants,

    /// Kill the command if it runs longer than this many seconds.
    ///
    /// Unset means no limit, matching a plain shell. The agent sets one of its
    /// own; at a terminal you already have Ctrl-C.
    #[arg(long = "timeout", value_name = "SECONDS")]
    timeout: Option<u64>,

    /// The command to run, and its arguments.
    // `last` keeps the separator meaningful: everything past `--` is the command's,
    // including flags sandbx defines. Not a `///`, which would reach `--help`.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    command: Vec<String>,
}

impl SandboxRun {
    /// The policy these flags describe.
    pub fn policy(&self) -> Result<SandboxPolicy, PolicyError> {
        self.grants.policy()
    }

    /// The program to run, split off from the arguments that follow it.
    ///
    /// Cannot panic: `required = true` on a `last` argument means clap rejects an empty
    /// command first.
    pub fn program(&self) -> &str {
        &self.command[0]
    }

    /// The program's arguments, empty when it was given none.
    pub fn arguments(&self) -> &[String] {
        &self.command[1..]
    }

    /// The `--timeout` seconds as a [`Duration`], or `None` for no limit.
    ///
    /// [`Duration`]: std::time::Duration
    pub fn timeout(&self) -> Option<std::time::Duration> {
        self.timeout.map(std::time::Duration::from_secs)
    }

    /// Run it, forward its output, and report the code to exit with.
    pub fn execute(&self) -> Result<i32, SandboxRunError> {
        let policy = self.policy()?;
        let mut command =
            SandboxedCommand::new(self.program(), policy.clone()).args(self.arguments());
        if let Some(limit) = self.timeout() {
            command = command.timeout(limit);
        }
        let output = command.output()?;

        // Interleaving is lost: `output()` runs the command to completion rather than
        // streaming.
        let _ = std::io::stdout().write_all(&output.stdout);
        let _ = std::io::stderr().write_all(&output.stderr);

        let code = sandbx_core::exit_code(&output.status);
        // After the command's own stderr, so sandbx's line is the last thing read.
        if let Some(advice) = resolver_advice(&policy, code) {
            eprintln!("sandbx: {advice}");
        }

        Ok(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ported() -> SandboxPolicy {
        SandboxPolicy::default().allow_network_port(443)
    }

    #[test]
    fn a_failed_run_under_a_port_list_advises_the_hint() {
        let advice = resolver_advice(&ported(), 6).expect("a failure under a port list");

        assert!(advice.contains("--dns-over-tcp"), "got: {advice}");
        assert!(advice.contains("--allow-read /etc"), "got: {advice}");
    }

    /// Nothing failed, so there is nothing to explain.
    #[test]
    fn a_successful_run_under_a_port_list_is_silent() {
        assert_eq!(resolver_advice(&ported(), 0), None);
    }

    /// The hint is already set, so whatever failed was not this.
    #[test]
    fn a_failed_run_with_the_hint_set_is_silent() {
        assert_eq!(resolver_advice(&ported().hint_dns_over_tcp(), 6), None);
    }

    /// Only a port allowlist denies UDP: under the other two shapes the resolver is
    /// either fully reachable or fully denied, and in both the advice would mislead.
    #[test]
    fn a_failed_run_without_a_port_list_is_silent() {
        assert_eq!(resolver_advice(&SandboxPolicy::default(), 6), None);
        assert_eq!(
            resolver_advice(&SandboxPolicy::default().allow_network(), 6),
            None
        );
    }
}
