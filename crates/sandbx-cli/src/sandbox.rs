//! `sandbox-run`: one command, under the boundary, and what it did.

use std::io::Write;

use sandbx_core::{NetworkPolicy, SandboxPolicy, SandboxedCommand, Sha256Digest};

use crate::{Grants, PolicyError, SandboxRunError};

/// Accept a digest `--pin-sha256` can carry, and refuse anything else.
///
/// In `Grants::variable_name`'s shape, and for its reason: the wire takes one spelling, so
/// the CLI says what to write rather than leaving a pasted digest to be refused two
/// processes later with no advice attached.
fn pin_digest(value: &str) -> Result<Sha256Digest, String> {
    Sha256Digest::parse(value).map_err(|error| {
        format!("{error} — `sandbx hash <file>` prints one in the form this takes")
    })
}

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

    /// Refuse the run unless the program hashes to this SHA-256. Not repeatable.
    ///
    /// Covers the one binary named after `--` and nothing it goes on to run
    /// itself, so `--allow-exec` still means "anything that appears under this
    /// path later". `sandbx hash PATH` prints a digest in the form this takes.
    ///
    /// The program must be an absolute path, and an ELF binary rather than a
    /// `#!` script: sandbx opens the file to hash it, so it resolves the name
    /// itself, and a bare one would be resolved against the `PATH` the *policy*
    /// gives the command rather than the one in your shell. Write
    /// `$PWD/target/debug/mytool`.
    ///
    /// It is not a path flag, so it grants nothing and does not replace the
    /// working-directory default.
    // On this struct and not `Grants`, which `agent-run` flattens too: there the program
    // is the agent's to choose, so the flag would parse, document a guarantee and pin
    // nothing. `Vec` and not `Option` because clap's default action on an `Option` is
    // last-wins, and two digests for one program is a mistake to report.
    #[arg(long = "pin-sha256", value_name = "HEX", value_parser = pin_digest)]
    pin_sha256: Vec<Sha256Digest>,

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

    /// The digest the program was pinned to, or why the pin cannot stand.
    ///
    /// Outside [`policy`](Self::policy), and outside `Grants` entirely: a pin grants
    /// nothing, so it must neither widen a policy nor suppress the working-directory
    /// default. The helper refuses a relative program too, but only here is the program in
    /// scope to name in the advice.
    pub fn pin(&self) -> Result<Option<Sha256Digest>, PolicyError> {
        let pin = match self.pin_sha256.as_slice() {
            [] => None,
            [only] => Some(*only),
            _ => return Err(PolicyError::RepeatedPin),
        };

        if pin.is_some() && !std::path::Path::new(self.program()).is_absolute() {
            return Err(PolicyError::PinNeedsAbsoluteProgram {
                program: self.program().to_string(),
            });
        }

        Ok(pin)
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
        let pin = self.pin()?;
        let unresolvable = cannot_resolve(&policy);
        let mut command = SandboxedCommand::new(self.program(), policy).args(self.arguments());
        if let Some(limit) = self.timeout() {
            command = command.timeout(limit);
        }
        if let Some(digest) = pin {
            command = command.pin_sha256(digest);
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

    /// A digest, as the parser would have produced it.
    fn digest() -> Sha256Digest {
        Sha256Digest::parse("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .expect("64 lowercase hex characters")
    }

    /// A run of `program`, pinned to `digests`.
    fn pinned(program: &str, digests: &[Sha256Digest]) -> SandboxRun {
        use clap::Parser as _;

        let mut argv = vec!["sandbx".to_string(), "sandbox-run".to_string()];
        for digest in digests {
            argv.push("--pin-sha256".to_string());
            argv.push(digest.to_string());
        }
        argv.push("--".to_string());
        argv.push(program.to_string());

        match crate::Cli::parse_from(argv).command {
            crate::Command::SandboxRun(run) => run,
            other => panic!("{other:?} is not sandbox-run"),
        }
    }

    #[test]
    fn a_single_pin_is_the_one_the_run_carries() {
        let run = pinned("/bin/true", &[digest()]);

        assert_eq!(run.pin().expect("one digest"), Some(digest()));
    }

    #[test]
    fn no_pin_flag_leaves_the_run_unpinned() {
        assert_eq!(pinned("/bin/true", &[]).pin().expect("no digest"), None);
    }

    /// Last-wins would quietly choose one of two images for one program.
    #[test]
    fn a_second_pin_is_refused() {
        let run = pinned("/bin/true", &[digest(), digest()]);

        assert!(
            matches!(run.pin(), Err(PolicyError::RepeatedPin)),
            "two digests were accepted"
        );
    }

    /// sandbx opens the file itself, so a bare name would be resolved against the policy's
    /// `PATH` — hashing one file and execing another.
    #[test]
    fn a_pin_on_a_relative_program_is_refused() {
        let run = pinned("target/debug/mytool", &[digest()]);

        let error = run
            .pin()
            .expect_err("a relative pinned program was accepted");

        assert!(
            error.to_string().contains("target/debug/mytool"),
            "the refusal did not name the program: {error}"
        );
    }

    /// An unpinned run keeps `execvp`'s own resolution, bare names included.
    #[test]
    fn a_relative_program_is_fine_unpinned() {
        assert_eq!(pinned("mytool", &[]).pin().expect("no digest"), None);
    }

    /// The parser owns the spelling, so this is where the operator is told what to write.
    #[test]
    fn a_digest_the_wire_could_not_carry_is_refused() {
        let good = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        for value in [
            "",
            &good[..63],
            &format!("{good}0")[..],
            &good.to_uppercase(),
        ] {
            let message = pin_digest(value).expect_err("accepted as a digest");

            assert!(
                message.contains("sandbx hash"),
                "{value:?} was refused without saying what to write: {message}"
            );
        }
    }

    /// Including the clause about the default a path flag replaces, which is the trap in
    /// the three flags it names.
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

    #[test]
    fn a_successful_run_is_silent() {
        assert_eq!(resolver_advice(true, 0), None);
    }

    #[test]
    fn a_port_list_without_53_cannot_resolve() {
        assert!(cannot_resolve(&ported()));
    }

    /// Advising it anyway would name a port the operator already has.
    #[test]
    fn a_port_list_naming_53_is_silent() {
        assert!(!cannot_resolve(&ported().allow_network_port(53)));
    }

    #[test]
    fn a_hinted_policy_is_silent() {
        assert!(!cannot_resolve(&ported().hint_dns_over_tcp()));
    }

    /// Only a port allowlist denies UDP; under the other two the resolver is fully
    /// reachable or fully denied, and the advice would mislead either way.
    #[test]
    fn no_port_list_is_silent() {
        assert!(!cannot_resolve(&SandboxPolicy::default()));
        assert!(!cannot_resolve(&SandboxPolicy::default().allow_network()));
    }
}
