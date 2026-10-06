//! The channel the helper reports what the parent cannot see on, and its wire format.
//!
//! The helper installs no `tracing` subscriber and must not — its stderr is a pipe the
//! parent replays verbatim — so it names what degraded and what it could not `exec`, and the
//! parent decodes and emits. What a record means is decided here, never by whatever wrote
//! the line. `context/decision-helper-audit-channel.md` for the stdin slot.

use std::fmt::Write as _;

/// Separates a mechanism from its detail on the wire; records are newline-separated.
///
/// A tab, because `detail` is prose built around `: ` and errno text. [`encode`] caps the
/// detail rather than escaping it: a detail is errno text from this crate, never input.
const SEPARATOR: char = '\t';

/// How much of a detail crosses.
///
/// The whole channel must fit a pipe buffer with nobody reading the other end — the parent
/// reads only once the helper has been waited on, so a stage blocked writing here would
/// deadlock the run it reports on. [`RECORD_LIMIT`] records of this length sit well inside
/// the 64 KiB a Linux pipe holds by default.
const DETAIL_LIMIT: usize = 256;

/// How many records [`decode`] will accept from one channel.
///
/// Each step reports at most once, and at most one refusal crosses however many stages
/// write, a stage reporting only from a region where the stage below it does not yet exist.
/// Anything beyond this did not come from [`encode`].
const RECORD_LIMIT: usize = Degradation::ALL.len() + 1;

/// What the helper reported on the channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Report<'a> {
    /// A hardening step that did not take effect, and why.
    Degraded(Degradation, &'a str),

    /// A helper stage refused rather than reaching the command, carrying the refusal's
    /// [`label`](crate::SandboxError::label).
    ///
    /// On the channel because the stage's non-zero exit is relayed on the command's behalf,
    /// so it would otherwise read as the command's own.
    Failed(&'static str),
}

/// A best-effort hardening step that did not take effect.
///
/// A closed set rather than a string: the parent turns these back into audit records, and a
/// label it accepted on trust would let whatever wrote the channel name the mechanism.
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
    /// Every step that can report here; drives `from_label` and [`RECORD_LIMIT`].
    pub(crate) const ALL: [Self; 2] = [Self::CapabilityBoundingSet, Self::UsernsIdentityMap];

    /// The stable name this step carries on the wire and in the audit trail.
    ///
    /// The one place a mechanism is spelled, and a trail is filtered by these strings, so
    /// they are a compatibility surface.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::CapabilityBoundingSet => "capability_bounding_set",
            Self::UsernsIdentityMap => "userns_identity_map",
        }
    }

    /// The step `label` names, if it names one at all.
    ///
    /// A lookup over [`ALL`](Self::ALL) rather than a second `match`, so a label
    /// [`label`](Self::label) can emit is one this accepts by construction.
    fn from_label(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|step| step.label() == label)
    }
}

/// Render records for the parent to read; empty when nothing degraded.
pub(crate) fn encode(records: &[(Degradation, String)]) -> String {
    let mut out = String::new();

    for (step, detail) in records {
        // Truncated on a character boundary, so the line stays UTF-8 for a `str` decoder.
        let detail: String = detail
            .chars()
            .filter(|c| *c != '\n' && *c != SEPARATOR)
            .take(DETAIL_LIMIT)
            .collect();

        let _ = writeln!(out, "{}{SEPARATOR}{detail}", step.label());
    }

    out
}

/// Render the record a stage that refused rather than becoming the command reports.
///
/// `'static` because this writes `label` as given, unlike [`encode`], so a `\t` in one would
/// forge a second record; [`SandboxError::label`](crate::SandboxError::label) is the only
/// source of one. No detail: the reason reaches the operator on the helper's stderr.
pub(crate) fn encode_refusal(label: &'static str) -> String {
    format!("{label}{SEPARATOR}\n")
}

/// Parse what the helper wrote back into the records it reported.
///
/// Skips an unrecognised line rather than failing the run, this being the reporting path for
/// a sandbox that already carried on. No label reaches the trail unvalidated, hence the two
/// closed sets below; they must stay disjoint, or the lookup order decides what one means.
pub(crate) fn decode(channel: &str) -> Vec<Report<'_>> {
    channel
        .lines()
        .filter_map(|line| {
            let (label, detail) = line.split_once(SEPARATOR)?;
            if let Some(step) = Degradation::from_label(label) {
                return Some(Report::Degraded(step, detail));
            }
            Some(Report::Failed(crate::SandboxError::reportable_label(
                label,
            )?))
        })
        .take(RECORD_LIMIT)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only the degradations in `channel`, for a test that is about those alone.
    fn degraded(channel: &str) -> Vec<(Degradation, &str)> {
        decode(channel)
            .into_iter()
            .filter_map(|report| match report {
                Report::Degraded(step, detail) => Some((step, detail)),
                Report::Failed(_) => None,
            })
            .collect()
    }

    #[test]
    fn every_step_survives_the_crossing_with_its_detail() {
        let records: Vec<_> = Degradation::ALL
            .into_iter()
            .map(|step| (step, format!("detail for {}", step.label())))
            .collect();

        let channel = encode(&records);
        let decoded = degraded(&channel);

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
    fn an_unrecognised_mechanism_is_refused() {
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
    fn a_malformed_line_keeps_the_records_around_it() {
        let channel = format!(
            "garbage\nnot_a_mechanism\tplausible\n{}\tleft as inherited\n",
            Degradation::CapabilityBoundingSet.label()
        );

        assert_eq!(
            decode(&channel),
            vec![Report::Degraded(
                Degradation::CapabilityBoundingSet,
                "left as inherited"
            )],
            "a surviving record was dropped with the malformed ones"
        );
    }

    #[test]
    fn a_long_detail_is_capped_rather_than_written_whole() {
        let encoded = encode(&[(Degradation::UsernsIdentityMap, "x".repeat(10_000))]);

        assert!(
            encoded.len() < DETAIL_LIMIT * 2,
            "a long detail was written whole: {} bytes",
            encoded.len()
        );

        let decoded = degraded(&encoded);
        assert_eq!(decoded.len(), 1, "the capped record stopped decoding");
        assert_eq!(
            decoded[0].0,
            Degradation::UsernsIdentityMap,
            "capping lost the mechanism"
        );
    }

    #[test]
    fn a_detail_cannot_forge_a_record_boundary() {
        let encoded = encode(&[(
            Degradation::UsernsIdentityMap,
            format!(
                "running as nobody\n{}\tforged",
                Degradation::CapabilityBoundingSet.label()
            ),
        )]);

        let decoded = degraded(&encoded);

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
    fn more_records_than_steps_are_not_all_accepted() {
        let line = format!("{}\tagain\n", Degradation::CapabilityBoundingSet.label());
        let channel = line.repeat(RECORD_LIMIT + 5);

        assert_eq!(
            decode(&channel).len(),
            RECORD_LIMIT,
            "the record cap did not hold"
        );
    }

    #[test]
    fn every_refusal_survives_the_round_trip() {
        for label in crate::SandboxError::REPORTED_BY_HELPER {
            assert_eq!(
                decode(&encode_refusal(label)),
                vec![Report::Failed(label)],
                "{label} did not cross as itself"
            );
        }
    }

    #[test]
    fn a_refusal_we_did_not_define_is_not_a_record() {
        let decoded = decode("not_a_refusal\t\n");

        assert!(
            decoded.is_empty(),
            "an unknown refusal reached the trail: {decoded:?}"
        );
    }

    /// The two lookups in `decode` run in sequence, so a shared label would make the order
    /// decide whether it is a mechanism or an outcome.
    #[test]
    fn no_degradation_label_is_also_a_refusal() {
        for step in Degradation::ALL {
            assert_eq!(
                crate::SandboxError::reportable_label(step.label()),
                None,
                "{} names both a degradation and a refusal",
                step.label()
            );
        }
    }

    /// The cap is one more than the steps for this record, so a channel carrying every
    /// degradation still has room for the refusal behind them — the worst case either stage
    /// can write.
    #[test]
    fn the_record_cap_admits_a_refusal_too() {
        let mut channel = encode(&Degradation::ALL.map(|step| (step, "degraded".to_string())));
        channel.push_str(&encode_refusal("process_hardening"));

        let decoded = decode(&channel);

        assert_eq!(decoded.len(), RECORD_LIMIT, "the cap dropped a record");
        assert_eq!(
            decoded.last(),
            Some(&Report::Failed("process_hardening")),
            "the refusal was capped away behind the degradations"
        );
    }

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
