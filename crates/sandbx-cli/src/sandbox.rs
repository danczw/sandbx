//! `sandbox-run`: one command, under the boundary, and what it did.

use std::io;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use sandbx_core::{NetworkPolicy, SandboxPolicy, SandboxedCommand, Sha256Digest};

use crate::{Grants, PolicyError, SandboxRunError};

/// Accept a digest `--pin-sha256` can carry, and refuse anything else.
///
/// Here rather than at the wire, so a pasted digest is refused with the advice attached
/// rather than two processes later without it.
fn pin_digest(value: &str) -> Result<Sha256Digest, String> {
    Sha256Digest::parse(value).map_err(|error| {
        format!("{error} — `sandbx hash <file>` prints one in the form this takes")
    })
}

/// Whether the policy leaves a name no way to resolve.
///
/// A port list denying UDP and not naming TCP 53 — the one shape where the advice below
/// names something the policy is actually missing. A policy bounding resolution asks no
/// nameserver, so a name it does not hold is refused on purpose and not for want of a port.
fn cannot_resolve(policy: &SandboxPolicy) -> bool {
    let unnamed = match policy.network() {
        NetworkPolicy::Ports(ports) => !ports.contains(&53),
        NetworkPolicy::Denied | NetworkPolicy::AnyPort => false,
    };
    unnamed && !policy.hints_dns_over_tcp() && !policy.bounds_resolution()
}

/// What such a run most likely needed, once it has failed.
///
/// Hedged: sandbx can't see the command's own `getaddrinfo`, so any failure gets this too.
/// Names both answers, except where `--allow-unix-sockets` is already held — that pair is
/// refused by `PolicyError::DnsWithUnixSockets`, and advice pointing at a refused answer is
/// worse than naming only one.
fn resolver_advice(cannot_resolve: bool, unix_sockets: bool, code: i32) -> Option<&'static str> {
    if !cannot_resolve || code == 0 {
        return None;
    }

    Some(if unix_sockets {
        "this port allowlist denies UDP and does not name TCP 53, so a name cannot \
         resolve. If that was the failure, add --dns-over-tcp --allow-network 53 \
         --allow-read /etc, remembering that a path flag replaces the working-directory \
         default. --allow-dns is the other answer, and this run cannot take it: a name \
         allowlist and --allow-unix-sockets are refused together, a local resolver \
         socket answering for every name"
    } else {
        "this port allowlist denies UDP and does not name TCP 53, so a name cannot \
         resolve. If that was the failure, either add --allow-dns NAME for each name the \
         command needs, which resolves them here and needs no further grant — or add \
         --dns-over-tcp --allow-network 53 --allow-read /etc, which lets any name \
         resolve, remembering that a path flag replaces the working-directory default"
    })
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
    // Not on `Grants`, which `agent-run` also flattens with no fixed program to pin.
    // `Vec` not `Option`: clap's `Option` action is last-wins, and two digests is a mistake.
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
    /// Outside [`policy`](Self::policy) and `Grants`: a pin must neither widen a policy nor
    /// suppress the cwd default. The helper also refuses a relative program, but only here
    /// can the advice name it.
    pub fn pin(&self) -> Result<Option<Sha256Digest>, PolicyError> {
        let pin = match self.pin_sha256.as_slice() {
            [] => None,
            [only] => Some(*only),
            _ => return Err(PolicyError::RepeatedPin),
        };

        if pin.is_some() && !Path::new(self.program()).is_absolute() {
            return Err(PolicyError::PinNeedsAbsoluteProgram {
                program: self.program().to_string(),
            });
        }

        Ok(pin)
    }

    /// The `--timeout` seconds as a [`Duration`], or `None` for no limit.
    ///
    /// [`Duration`]: std::time::Duration
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout.map(Duration::from_secs)
    }

    /// Run it, forward its output, and report the code to exit with.
    pub fn execute(&self) -> Result<i32, SandboxRunError> {
        let policy = self.policy()?;
        let pin = self.pin()?;
        let unresolvable = cannot_resolve(&policy);
        let unix_sockets = policy.allows_unix_sockets();
        let mut command = SandboxedCommand::new(self.program(), policy).args(self.arguments());
        if let Some(limit) = self.timeout() {
            command = command.timeout(limit);
        }
        if let Some(digest) = pin {
            command = command.pin_sha256(digest);
        }
        let output = command.output()?;

        // Interleaving is lost: `output()` runs to completion rather than streaming.
        let _ = io::stdout().write_all(&output.stdout);
        let _ = io::stderr().write_all(&output.stderr);

        let code = sandbx_core::exit_code(&output.status);
        // After the command's own stderr, so sandbx's line is the last thing read.
        if let Some(advice) = resolver_advice(unresolvable, unix_sockets, code) {
            eprintln!("sandbx: {advice}");
        }

        Ok(code)
    }
}

#[cfg(test)]
#[path = "sandbox_tests.rs"]
mod tests;
