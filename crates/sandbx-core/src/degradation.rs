//! The channel the helper reports what the parent cannot see on, and its wire format. The
//! helper installs no `tracing` subscriber and must not — its stderr is a pipe the parent
//! replays verbatim — so it names what degraded and what it could not `exec`, and the
//! parent decodes and emits. What a record means is decided here, never by whatever wrote
//! the line (`context/decision-helper-audit-channel.md`).

use std::fmt::Write as _;

/// Separates a mechanism from its detail on the wire; records are newline-separated. A
/// tab, because `detail` is prose built around `: ` and errno text. [`encode`] caps the
/// detail rather than escaping it: a detail is errno text from this crate, never input.
const SEPARATOR: char = '\t';

/// How much of a detail crosses. The whole channel must fit a pipe buffer with nobody
/// reading the other end — the parent reads only once the helper has been waited on, so a
/// stage blocked writing here would deadlock the run it reports on. [`RECORD_LIMIT`]
/// records of this length sit well inside the 64 KiB a Linux pipe holds by default.
const DETAIL_LIMIT: usize = 256;

/// How many records [`decode`] will accept from one channel. Each step reports at most
/// once, and at most one refusal crosses however many stages write, a stage reporting only
/// from a region where the stage below it does not yet exist. Anything beyond this did not
/// come from [`encode`].
const RECORD_LIMIT: usize = Degradation::ALL.len() + 1;

/// What the helper reported on the channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Report {
    /// A hardening step that did not take effect, and why.
    Degraded(Degraded),

    /// A helper stage refused rather than reaching the command. On the channel because the
    /// stage's non-zero exit is relayed on the command's behalf, so it would otherwise read
    /// as the command's own.
    Failed(crate::HelperRefusal),
}

/// A best-effort hardening step that did not take effect. A closed set rather than a
/// string: the parent turns these back into audit records, and a label it accepted on
/// trust would let whatever wrote the channel name the mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Degradation {
    /// `PR_CAPBSET_DROP` was refused, so the capability bounding set is left as
    /// inherited. A weaker sandbox — see `SECURITY.md`.
    CapabilityBoundingSet,

    /// The uid/gid map could not be written, so the process reads back as the overflow
    /// uid. Costs uid fidelity only, and is if anything more restrictive.
    UsernsIdentityMap,

    /// A name `--allow-dns` listed resolved to no address, so nothing in the command's hosts
    /// file reaches it: more restrictive, and indistinguishable from the flag working.
    UnresolvedDnsName,
}

impl Degradation {
    /// Every step that can report here; drives `from_label` and [`RECORD_LIMIT`].
    pub(crate) const ALL: [Self; 3] = [
        Self::CapabilityBoundingSet,
        Self::UsernsIdentityMap,
        Self::UnresolvedDnsName,
    ];

    /// The stable name this step carries on the wire and in the audit trail: the one place a
    /// mechanism is spelled, and a trail filtered by these strings makes it a compatibility
    /// surface.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::CapabilityBoundingSet => "capability_bounding_set",
            Self::UsernsIdentityMap => "userns_identity_map",
            Self::UnresolvedDnsName => "unresolved_dns_name",
        }
    }

    /// The step `label` names, if it names one at all. A lookup over [`ALL`](Self::ALL)
    /// rather than a second `match`, so a label [`label`](Self::label) can emit is one this
    /// accepts by construction.
    fn from_label(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|step| step.label() == label)
    }
}

/// A hardening step that did not take effect, and why: what the helper encodes, and what
/// the parent decodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Degraded {
    pub(crate) step: Degradation,
    /// Owned at both ends: built from an errno, and copied off the channel once per run,
    /// for at most [`RECORD_LIMIT`] records.
    pub(crate) detail: String,
}

/// Render records for the parent to read; empty when nothing degraded.
pub(crate) fn encode(records: &[Degraded]) -> String {
    let mut out = String::new();

    for Degraded { step, detail } in records {
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

/// Render the record a stage that refused rather than starting the command reports. A
/// [`HelperRefusal`](crate::HelperRefusal) and not a string: this writes the label as
/// given, unlike [`encode`], so a `\t` in one would forge a second record and the type
/// makes one unrepresentable. No detail — the reason travels on the helper's stderr instead.
pub(crate) fn encode_refusal(refusal: crate::HelperRefusal) -> String {
    format!("{}{SEPARATOR}\n", refusal.label())
}

/// Parse what the helper wrote back into the records it reported. Skips an unrecognised
/// line rather than failing the run, this being the reporting path for a sandbox that
/// already carried on. No label reaches the trail unvalidated, hence the two closed sets
/// below; they must stay disjoint, or the lookup order decides what one means.
pub(crate) fn decode(channel: &str) -> Vec<Report> {
    channel
        .lines()
        .filter_map(|line| {
            let (label, detail) = line.split_once(SEPARATOR)?;
            if let Some(step) = Degradation::from_label(label) {
                return Some(Report::Degraded(Degraded {
                    step,
                    detail: detail.to_owned(),
                }));
            }
            Some(Report::Failed(crate::HelperRefusal::from_label(label)?))
        })
        .take(RECORD_LIMIT)
        .collect()
}

#[cfg(test)]
#[path = "degradation_tests.rs"]
mod tests;
