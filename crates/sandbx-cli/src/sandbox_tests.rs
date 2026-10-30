use super::{SandboxRun, cannot_resolve, pin_digest, resolver_advice};
use crate::PolicyError;
use sandbx_core::{SandboxPolicy, Sha256Digest};

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

/// sandbx opens the file itself, so a bare name would hash one file and exec another.
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

/// Includes the clause that a path flag replaces the working-directory default.
#[test]
fn a_failed_unresolvable_run_advises_every_flag_it_needs() {
    let advice = resolver_advice(&ported(), 6).expect("a failure with no way to resolve");

    assert!(advice.contains("--allow-dns NAME"), "got: {advice}");
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
    assert_eq!(resolver_advice(&ported(), 0), None);
}

/// The control for the cases around it: a failure is not advised where a name can resolve.
#[test]
fn a_failed_run_that_could_resolve_is_not_advised() {
    assert_eq!(resolver_advice(&ported().allow_network_port(53), 6), None);
}

#[test]
fn a_run_holding_unix_sockets_is_not_advised_to_add_a_name_allowlist() {
    let advice = resolver_advice(&ported().allow_unix_sockets(), 6)
        .expect("a failure with no way to resolve");

    assert!(
        !advice.contains("add --allow-dns"),
        "advised a flag --allow-unix-sockets makes PolicyError::DnsWithUnixSockets: {advice}"
    );
    assert!(advice.contains("--dns-over-tcp"), "got: {advice}");
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

/// A name it does not hold is refused on purpose, so naming a missing port would mislead.
#[test]
fn a_policy_bounding_resolution_is_silent() {
    assert!(!cannot_resolve(&ported().allow_dns("example.com")));
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
