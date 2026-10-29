use super::{HelperRefusal, STDERR_LIMIT};
use crate::SandboxError;

#[test]
fn every_refusal_round_trips_through_its_own_label() {
    for refusal in HelperRefusal::ALL {
        assert_eq!(
            HelperRefusal::from_label(refusal.label()),
            Some(refusal),
            "{refusal:?} does not round-trip through its own label"
        );
    }
}

#[test]
fn no_two_refusals_share_a_label() {
    let mut labels: Vec<_> = HelperRefusal::ALL.iter().map(|r| r.label()).collect();
    labels.sort_unstable();
    let total = labels.len();
    labels.dedup();

    assert_eq!(labels.len(), total, "two refusals share a label");
}

/// The relayed detail is printed by a caller that prefixes it again, so carrying the
/// helper's own announcement through would read as `sandbx: sandbx: sandbox helper failed:`.
#[test]
fn a_relayed_refusal_does_not_announce_itself_twice() {
    let said = "/bin/true is not the binary it was pinned to";
    let stderr = format!(
        "{}{said}\n",
        crate::command::dispatch::HELPER_FAILURE_PREFIX
    )
    .into_bytes();

    let SandboxError::HelperRefused { detail, .. } = HelperRefusal::PinMismatch.relayed(&stderr)
    else {
        unreachable!("`relayed` returns the variant it names");
    };

    assert_eq!(detail, said, "the helper's own prefix was relayed");
}

/// Nothing downstream bounds it: a `tool_result` carries this to a model, and
/// `ToolLimits::max_bytes` caps a command's output rather than an error's detail.
#[test]
fn a_helper_that_printed_too_much_is_truncated() {
    let SandboxError::HelperRefused { detail, .. } =
        HelperRefusal::Landlock.relayed(&vec![b'x'; STDERR_LIMIT * 2])
    else {
        unreachable!("`relayed` returns the variant it names");
    };

    assert_eq!(detail.chars().count(), STDERR_LIMIT, "the cap did not hold");
}

#[test]
fn a_label_we_did_not_define_is_refused() {
    for label in ["", "not_a_refusal", "seccomp ", "SECCOMP"] {
        assert_eq!(
            HelperRefusal::from_label(label),
            None,
            "{label:?} was accepted as one of our labels"
        );
    }
}
