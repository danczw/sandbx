//! The channel a best-effort hardening step reports itself on, and the wire
//! format it crosses as.
//!
//! Both best-effort steps run in the re-exec'd helper's first stage, which
//! installs no `tracing` subscriber — so emitting an
//! [`AuditEvent::Degraded`](crate::AuditEvent::Degraded) there records nothing
//! at all, however the level is set (#95). A subscriber in the helper is not the
//! answer either: that process's stderr is a pipe the parent replays verbatim,
//! and the stage below it becomes the sandboxed command, so sandbx's own records
//! would land in the output of the command being confined.
//!
//! So the helper does not emit. It names what degraded, this module renders that
//! as bytes, and the *parent* turns the bytes back into audit events on the one
//! subscriber the process tree has. The crossing is one-way and carries no
//! policy: what a degradation means is decided here, not by whatever wrote the
//! line.
//!
//! See `context/decision-helper-audit-channel.md` for why the bytes travel in
//! the stdin slot rather than on a descriptor of their own.

use std::fmt::Write as _;

/// Separates a mechanism from its detail on the wire.
///
/// A tab, because `detail` is prose built around `: ` and errno text and would
/// collide with anything more ordinary. Records themselves are newline-separated,
/// which is why [`encode`] caps the detail rather than escaping it: a detail is
/// built from an errno in this crate, never from input, so the cap is a bound and
/// not a sanitiser.
const SEPARATOR: char = '\t';

/// How much of a detail crosses.
///
/// The whole channel has to fit a pipe buffer without anyone reading the other
/// end — the parent reads only once the helper has been waited on, so a stage 1
/// that blocked writing here would deadlock the run it is reporting on. Two
/// records of this length are three orders of magnitude inside the 64 KiB a
/// Linux pipe holds by default, which is what makes "it never blocks" a property
/// of the format rather than a hope about errno strings.
const DETAIL_LIMIT: usize = 256;

/// How many records [`decode`] will accept from one channel.
///
/// There are [`Degradation::ALL`]`.len()` steps that can report, each at most
/// once, so anything beyond that did not come from [`encode`]. Refusing the
/// excess keeps a malformed channel from growing the audit trail without bound;
/// it is not a trust boundary, because by the time the sandboxed command exists
/// the write end is already gone (see `helper::exec_sandboxed`).
const RECORD_LIMIT: usize = Degradation::ALL.len();

/// A best-effort hardening step that did not take effect.
///
/// A closed set rather than a string, because the parent turns these back into
/// audit records: a label it accepted on trust would let whatever wrote the
/// channel choose what the trail says a mechanism was called.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Degradation {
    /// `PR_CAPBSET_DROP` was refused, so the capability bounding set is left as
    /// inherited. A weaker sandbox — see `SECURITY.md`.
    CapabilityBoundingSet,

    /// The uid/gid map could not be written, so the process reads back as the
    /// overflow uid. Costs uid fidelity only, and is if anything more
    /// restrictive.
    UsernsIdentityMap,
}

impl Degradation {
    /// Every step that can report on this channel.
    ///
    /// Drives [`from_label`](Self::from_label) and [`RECORD_LIMIT`], so a new
    /// variant is decodable and accounted for by being added here rather than by
    /// being remembered in three places.
    pub(crate) const ALL: [Self; 2] = [Self::CapabilityBoundingSet, Self::UsernsIdentityMap];

    /// The stable name this step carries on the wire and in the audit trail.
    ///
    /// The one place a mechanism is spelled. `AuditEvent::Degraded.mechanism` is
    /// documented as a label to filter a trail by, so these strings are a
    /// compatibility surface and not an implementation detail.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::CapabilityBoundingSet => "capability_bounding_set",
            Self::UsernsIdentityMap => "userns_identity_map",
        }
    }

    /// The step `label` names, if it names one at all.
    ///
    /// A lookup over [`ALL`](Self::ALL) rather than a second `match`, for the
    /// reason [`axis_for`](crate::helper_args) is written the same way: a label
    /// [`label`](Self::label) can emit is one this accepts, by construction,
    /// rather than by two lists agreeing.
    fn from_label(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|step| step.label() == label)
    }
}

/// Render records for the parent to read.
///
/// Empty in the ordinary case — nothing degraded — and the caller writes nothing
/// at all then, so a run on a host where hardening works costs no bytes.
pub(crate) fn encode(records: &[(Degradation, String)]) -> String {
    let mut out = String::new();

    for (step, detail) in records {
        // Truncated on a character boundary, so the line stays UTF-8 for a
        // decoder that reads it back as `str`. A detail long enough to hit this
        // is an errno string from a kernel this code has not seen; losing its
        // tail beats losing the record.
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
/// Skips a line it does not recognise rather than failing the run: this is the
/// reporting path for a sandbox that already carried on, so a channel that
/// arrives malformed should cost the record and nothing else. What it must not
/// do is pass an unvalidated mechanism name through to the trail, which is why
/// the label goes through [`Degradation::from_label`].
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

    /// The property the channel exists for: what stage 1 named is what the
    /// parent emits. Both steps, because each is spelled once and a swap between
    /// them would be invisible to a test that only checked one.
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

    /// Nothing degraded is the ordinary case, and it has to cost nothing: the
    /// caller writes `encode`'s output verbatim, so a stray byte here would be a
    /// record on every successful run.
    #[test]
    fn nothing_degraded_encodes_to_nothing() {
        assert_eq!(encode(&[]), "", "a run with no degradation wrote bytes");
        assert!(decode("").is_empty(), "empty input decoded to a record");
    }

    /// The reason the wire carries a label and not free text. The parent emits
    /// what it decodes straight onto the audit trail, so a mechanism name it
    /// accepted on trust would let the writer of this line decide what the trail
    /// says a mechanism was called.
    #[test]
    fn an_unrecognised_mechanism_is_refused_rather_than_echoed() {
        let decoded = decode("not_a_mechanism\tsomething plausible\n");

        assert!(
            decoded.is_empty(),
            "an unknown mechanism reached the trail: {decoded:?}"
        );
    }

    /// A line with no separator names no detail, and half a record is not one.
    /// Skipped rather than read as a mechanism with an empty detail, which would
    /// put a decision on the trail that nothing reported.
    #[test]
    fn a_line_with_no_separator_is_not_a_record() {
        for line in ["capability_bounding_set", "", "   ", "userns_identity_map "] {
            assert!(
                decode(line).is_empty(),
                "{line:?} has no separator, so it carries no detail"
            );
        }
    }

    /// A malformed line costs its own record and no others. The channel is the
    /// reporting path for a sandbox that already carried on, so one bad line must
    /// not take the good ones with it.
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

    /// The parent reads only after the helper has been waited on, so stage 1
    /// writes into a pipe nobody is draining. The cap is what keeps that from
    /// deadlocking the very run it is reporting on, so it is pinned here rather
    /// than left to errno strings being short in practice.
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

    /// A newline in a detail would split one record into two, and a tab would move
    /// the boundary between mechanism and detail — so a detail shaped like a record
    /// of its own would put a second `degraded` decision on the trail that no step
    /// reported. Neither character can arise from an errno today; the format holds
    /// rather than relying on that.
    ///
    /// What is pinned is the *record* count and the mechanism, not the absence of
    /// the other label's text: once the separators are gone the label is inert
    /// prose inside one detail, which is the mechanism this test is checking
    /// disarmed it.
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

    /// More records than there are steps did not come from `encode`, and the
    /// trail should not grow without bound on the word of a channel that is
    /// already malformed.
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

    /// Every step has a distinct label, since the label is what the trail is
    /// filtered by: two steps sharing one would make a `degraded` record
    /// ambiguous about which mechanism it names, and `from_label` would resolve
    /// it to whichever came first in `ALL`.
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
