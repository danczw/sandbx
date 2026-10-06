//! `sandbox-run`: one command, under the boundary, and what it did.

use std::io::Write;

use sandbx_core::{NetworkPolicy, SandboxPolicy, SandboxedCommand};

use crate::{Grants, PolicyError, SandboxRunError};

/// Whether the policy leaves a name no way to resolve.
///
/// A port list denying UDP *and* not naming TCP 53, which is the one shape where the
/// advice below names something the policy is actually missing.
fn cannot_resolve(policy: &SandboxPolicy) -> bool {
    let unnamed = match policy.network() {
        NetworkPolicy::Ports(ports) => !ports.contains(&53),
        NetworkPolicy::Denied | NetworkPolicy::AnyPort => false,
    };
    unnamed && !policy.hints_dns_over_tcp()
}

/// What such a run most likely needed, once it has failed.
///
/// Hedged, and it has to be: sandbx cannot see the command's own `getaddrinfo`, so a
/// failure for any other reason gets this too.
fn resolver_advice(cannot_resolve: bool, code: i32) -> Option<&'static str> {
    match cannot_resolve && code != 0 {
        true => Some(
            "this port allowlist denies UDP and does not name TCP 53, so a name cannot \
             resolve. If that was the failure, add --dns-over-tcp --allow-network 53 \
             --allow-read /etc — and a path flag replaces the working-directory default, \
             so name the tree the command needs too",
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
        // Before the policy moves: the advice needs one bit of it, not a clone of all of it.
        let unresolvable = cannot_resolve(&policy);
        let mut command = SandboxedCommand::new(self.program(), policy).args(self.arguments());
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
        if let Some(advice) = resolver_advice(unresolvable, code) {
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

    /// Everything the advice tells the operator to type, including the clause about the
    /// default it replaces — the trap of the three flags it names.
    #[test]
    fn a_failed_unresolvable_run_advises_every_flag_it_needs() {
        let advice = resolver_advice(true, 6).expect("a failure with no way to resolve");

        assert!(advice.contains("--dns-over-tcp"), "got: {advice}");
        assert!(advice.contains("--allow-network 53"), "got: {advice}");
        assert!(advice.contains("--allow-read /etc"), "got: {advice}");
        assert!(
            advice.contains("replaces the working-directory default"),
            "the advice does not say a path flag suppresses the default: {advice}"
        );
    }

    /// Nothing failed, so there is nothing to explain.
    #[test]
    fn a_successful_run_is_silent() {
        assert_eq!(resolver_advice(true, 0), None);
    }

    #[test]
    fn a_port_list_without_53_cannot_resolve() {
        assert!(cannot_resolve(&ported()));
    }

    /// The policy already names what the advice would ask for, so a failure here was
    /// something else — and advising it anyway would name a port the operator has.
    #[test]
    fn a_port_list_naming_53_is_silent() {
        assert!(!cannot_resolve(&ported().allow_network_port(53)));
    }

    /// The hint is set, so the remaining gap is the operator's to see on the port list.
    #[test]
    fn a_hinted_policy_is_silent() {
        assert!(!cannot_resolve(&ported().hint_dns_over_tcp()));
    }

    /// Only a port allowlist denies UDP: under the other two shapes the resolver is
    /// either fully reachable or fully denied, and in both the advice would mislead.
    #[test]
    fn no_port_list_is_silent() {
        assert!(!cannot_resolve(&SandboxPolicy::default()));
        assert!(!cannot_resolve(&SandboxPolicy::default().allow_network()));
    }
}
