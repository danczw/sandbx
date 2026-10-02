//! The channel a best-effort hardening step reports itself on, and its wire format.
//!
//! The helper's first stage installs no `tracing` subscriber and must not — its stderr is
//! a pipe the parent replays verbatim, and the stage below becomes the sandboxed command.
//! So the helper names what degraded, this module renders bytes, and the *parent* turns
//! them back into audit events. What a degradation means is decided here, never by
//! whatever wrote the line. See `context/decision-helper-audit-channel.md` for why the
//! bytes travel in the stdin slot.

use std::fmt::Write as _;

/// Separates a mechanism from its detail on the wire; records are newline-separated.
///
/// A tab, because `detail` is prose built around `: ` and errno text. [`encode`] caps the
/// detail rather than escaping it: a detail comes from an errno in this crate, never from
/// input, so the cap is a bound and not a sanitiser.
const SEPARATOR: char = '\t';

/// How much of a detail crosses.
///
/// The whole channel must fit a pipe buffer with nobody reading the other end — the
/// parent reads only once the helper has been waited on, so a stage 1 that blocked writing
/// here would deadlock the run it is reporting on. Two records of this length are three
/// orders of magnitude inside the 64 KiB a Linux pipe holds by default.
const DETAIL_LIMIT: usize = 256;

/// How many records [`decode`] will accept from one channel.
///
/// Each step reports at most once, so anything beyond this did not come from [`encode`],
/// and refusing the excess keeps a malformed channel from growing the audit trail without
/// bound. Not a trust boundary: by the time the sandboxed command exists the write end is
/// already gone (see `helper::exec_sandboxed`).
const RECORD_LIMIT: usize = Degradation::ALL.len();

/// A best-effort hardening step that did not take effect.
///
/// A closed set rather than a string: the parent turns these back into audit records, and
/// a label it accepted on trust would let whatever wrote the channel choose what the trail
/// says a mechanism was called.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Degradation {
    /// `PR_CAPBSET_DROP` was refused, so the capability bounding set is left as
    /// inherited. A weaker sandbox — see `SECURITY.md`.
    CapabilityBoundingSet,

    /// The uid/gid map could not be written, so the process reads back as the overflow
    /// uid. Costs uid fidelity only, and is if anything more restrictive.
    UsernsIdentityMap,
}

impl Degradation {
    /// Every step that can report on this channel.
    ///
    /// Drives [`from_label`](Self::from_label) and [`RECORD_LIMIT`], so a new variant is
    /// decodable and accounted for by being added here.
    pub(crate) const ALL: [Self; 2] = [Self::CapabilityBoundingSet, Self::UsernsIdentityMap];

    /// The stable name this step carries on the wire and in the audit trail.
    ///
    /// The one place a mechanism is spelled, and a trail is filtered by these strings, so
    /// they are a compatibility surface rather than an implementation detail.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::CapabilityBoundingSet => "capability_bounding_set",
            Self::UsernsIdentityMap => "userns_identity_map",
        }
    }

    /// The step `label` names, if it names one at all.
    ///
    /// A lookup over [`ALL`](Self::ALL) rather than a second `match`: a label
    /// [`label`](Self::label) can emit is one this accepts by construction.
    fn from_label(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|step| step.label() == label)
    }
}

/// Render records for the parent to read; empty when nothing degraded.
pub(crate) fn encode(records: &[(Degradation, String)]) -> String {
    let mut out = String::new();

    for (step, detail) in records {
        // Truncated on a character boundary, so the line stays UTF-8 for a decoder that
        // reads it back as `str`.
        let detail: String = detail
            .chars()
            .filter(|c| *c != '\n' && *c != SEPARATOR)
            .take(DETAIL_LIMIT)
            .collect();

        let _ = writeln!(out, "{}{SEPARATOR}{detail}", step.label());
    }

    out
}

/// Parse what the helper wrote back into steps and their details.
///
/// Skips an unrecognised line rather than failing the run: this is the reporting path for
/// a sandbox that already carried on. What it must not do is pass an unvalidated mechanism
/// name through to the trail, hence [`Degradation::from_label`].
pub(crate) fn decode(channel: &str) -> Vec<(Degradation, &str)> {
    channel
        .lines()
        .filter_map(|line| {
            let (label, detail) = line.split_once(SEPARATOR)?;
            Some((Degradation::from_label(label)?, detail))
        })
        .take(RECORD_LIMIT)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_step_survives_the_crossing_with_its_detail() {
        let records: Vec<_> = Degradation::ALL
            .into_iter()
            .map(|step| (step, format!("detail for {}", step.label())))
            .collect();

        let channel = encode(&records);
        let decoded = decode(&channel);

        assert_eq!(decoded.len(), records.len(), "a record was lost");
        for ((sent, detail), (got, got_detail)) in records.iter().zip(decoded) {
            assert_eq!(*sent, got, "the step changed in transit");
            assert_eq!(detail, got_detail, "the detail changed in transit");
        }
    }

    #[test]
    fn nothing_degraded_encodes_to_nothing() {
        assert_eq!(encode(&[]), "", "a run with no degradation wrote bytes");
        assert!(decode("").is_empty(), "empty input decoded to a record");
    }

    #[test]
    fn an_unrecognised_mechanism_is_refused_rather_than_echoed() {
        let decoded = decode("not_a_mechanism\tsomething plausible\n");

        assert!(
            decoded.is_empty(),
            "an unknown mechanism reached the trail: {decoded:?}"
        );
    }

    #[test]
    fn a_line_with_no_separator_is_not_a_record() {
        for line in ["capability_bounding_set", "", "   ", "userns_identity_map "] {
            assert!(
                decode(line).is_empty(),
                "{line:?} has no separator, so it carries no detail"
            );
        }
    }

    #[test]
    fn a_malformed_line_does_not_discard_the_records_around_it() {
        let channel = format!(
            "garbage\nnot_a_mechanism\tplausible\n{}\tleft as inherited\n",
            Degradation::CapabilityBoundingSet.label()
        );

        assert_eq!(
            decode(&channel),
            vec![(Degradation::CapabilityBoundingSet, "left as inherited")],
            "a surviving record was dropped with the malformed ones"
        );
    }

    /// Stage 1 writes into a pipe nobody drains until the helper is waited on, so the cap
    /// is what keeps the report from deadlocking the run.
    #[test]
    fn a_long_detail_is_capped_rather_than_written_whole() {
        let encoded = encode(&[(Degradation::UsernsIdentityMap, "x".repeat(10_000))]);

        assert!(
            encoded.len() < DETAIL_LIMIT * 2,
            "a long detail was written whole: {} bytes",
            encoded.len()
        );

        let decoded = decode(&encoded);
        assert_eq!(decoded.len(), 1, "the capped record stopped decoding");
        assert_eq!(
            decoded[0].0,
            Degradation::UsernsIdentityMap,
            "capping lost the mechanism"
        );
    }

    /// A newline would split one record into two and a tab would move the mechanism/detail
    /// boundary, putting a `degraded` decision on the trail that no step reported.
    #[test]
    fn a_detail_cannot_forge_a_record_boundary() {
        let encoded = encode(&[(
            Degradation::UsernsIdentityMap,
            format!(
                "running as nobody\n{}\tforged",
                Degradation::CapabilityBoundingSet.label()
            ),
        )]);

        let decoded = decode(&encoded);

        assert_eq!(decoded.len(), 1, "a detail split itself into two records");
        assert_eq!(
            decoded[0].0,
            Degradation::UsernsIdentityMap,
            "a forged mechanism displaced the one that reported"
        );
        assert!(
            !decoded[0].1.contains('\n') && !decoded[0].1.contains(SEPARATOR),
            "a separator survived into the detail: {:?}",
            decoded[0].1
        );
    }

    #[test]
    fn more_records_than_there_are_steps_are_not_all_accepted() {
        let line = format!("{}\tagain\n", Degradation::CapabilityBoundingSet.label());
        let channel = line.repeat(RECORD_LIMIT + 5);

        assert_eq!(
            decode(&channel).len(),
            RECORD_LIMIT,
            "the record cap did not hold"
        );
    }

    /// The label is what a trail is filtered by, so two steps sharing one would make a
    /// record ambiguous and `from_label` would resolve it to whichever came first in `ALL`.
    #[test]
    fn no_two_steps_share_a_label() {
        for step in Degradation::ALL {
            assert_eq!(
                Degradation::from_label(step.label()),
                Some(step),
                "{:?} does not round-trip through its own label",
                step
            );
        }

        let mut labels: Vec<_> = Degradation::ALL.iter().map(|s| s.label()).collect();
        labels.sort_unstable();
        let total = labels.len();
        labels.dedup();

        assert_eq!(labels.len(), total, "two steps share a label");
    }
}
