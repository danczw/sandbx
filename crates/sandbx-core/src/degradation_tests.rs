use super::{
    DETAIL_LIMIT, Degradation, RECORD_LIMIT, Report, SEPARATOR, decode, encode, encode_refusal,
};

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
    for refusal in crate::HelperRefusal::ALL {
        assert_eq!(
            decode(&encode_refusal(refusal)),
            vec![Report::Failed(refusal)],
            "{refusal:?} did not cross as itself"
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
            crate::HelperRefusal::from_label(step.label()),
            None,
            "{} names both a degradation and a refusal",
            step.label()
        );
    }
}

/// The cap is one more than the steps, so a channel carrying every degradation still has
/// room for the refusal behind them — the worst case either stage can write.
#[test]
fn the_record_cap_admits_a_refusal_too() {
    let mut channel = encode(&Degradation::ALL.map(|step| (step, "degraded".to_string())));
    channel.push_str(&encode_refusal(crate::HelperRefusal::ProcessHardening));

    let decoded = decode(&channel);

    assert_eq!(decoded.len(), RECORD_LIMIT, "the cap dropped a record");
    assert_eq!(
        decoded.last(),
        Some(&Report::Failed(crate::HelperRefusal::ProcessHardening)),
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
