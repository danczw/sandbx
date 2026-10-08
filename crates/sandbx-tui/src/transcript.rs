//! What the screen shows, folded from the event stream one event at a time.
//!
//! No terminal behind it, so the fold is a unit test rather than a screenshot. Nothing
//! here renders a *requested* call: only a settled one has an outcome.

use sandbx_providers::AgentEvent;

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

    /// The last reported prompt and output counts, `None` while nothing was reported.
    tokens: Option<(u32, u32)>,
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
            tokens: None,
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
            } => self.tokens = Some((input_tokens.unwrap_or(0), output_tokens.unwrap_or(0))),
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

    pub(crate) fn tokens(&self) -> Option<(u32, u32)> {
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

    fn push(&mut self, kind: Kind, text: &str) {
        self.entries.push(Entry {
            kind,
            text: printable(text),
        });
    }
}

/// Model-chosen text as it may be written to a cell.
///
/// ratatui puts a cell's content on the terminal as given, so an escape sequence inside an
/// answer would rewrite the screen around it. Replaced with U+FFFD rather than dropped:
/// dropped, a hostile string reads as plausible prose. `\n` survives as the break the view
/// splits on, and a tab becomes spaces, nothing rendering a cell that holds one.
fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());

    for c in text.chars() {
        match c {
            '\n' => out.push('\n'),
            '\t' => out.push_str("    "),
            c if c.is_control() => out.push('\u{fffd}'),
            c => out.push(c),
        }
    }

    out
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
    /// blocks carry replay material, and a signature is opaque — rendering one is how it
    /// ends up read, copied or scrolled back to.
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

    /// The break the view splits on, and the tab nothing renders.
    #[test]
    fn a_newline_survives_and_a_tab_becomes_spaces() {
        assert_eq!(printable("one\ntwo\tthree"), "one\ntwo    three");
    }

    #[test]
    fn an_empty_delta_opens_no_entry() {
        assert_eq!(
            folded(&[text(""), thinking("")], true),
            vec![entry(Kind::Prompt, PROMPT)]
        );
    }

    /// Anthropic restates the counts cumulatively, so the last figures are the turn's.
    #[test]
    fn rounds_are_counted_from_stops_and_usage_is_the_last_reported() {
        let mut transcript = Transcript::new(PROMPT, false);
        assert_eq!((transcript.rounds(), transcript.tokens()), (0, None));

        for reason in [
            sandbx_providers::StopReason::ToolUse,
            sandbx_providers::StopReason::EndTurn,
        ] {
            transcript.event(&AgentEvent::Stop { reason });
        }
        for tokens in [(900, 32), (1200, 64)] {
            transcript.event(&AgentEvent::Usage {
                input_tokens: Some(tokens.0),
                output_tokens: Some(tokens.1),
                cache_write_tokens: None,
                cache_read_tokens: None,
            });
        }

        assert_eq!(transcript.rounds(), 2);
        assert_eq!(transcript.tokens(), Some((1200, 64)));
    }
}
