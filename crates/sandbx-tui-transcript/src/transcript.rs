//! What the screen shows, folded from the event stream one event at a time.
//!
//! No terminal behind it, so the fold is a unit test rather than a screenshot. Nothing
//! here renders a *requested* call: only a settled one has an outcome.

use sandbx_event::AgentEvent;
use sandbx_text::invisible;

use crate::view::GUTTER_MARK;

/// What one block of the transcript is, which is also how the view colours it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Prompt,
    Answer,
    /// Present only when it was asked for.
    Reasoning,
    /// A line the harness wrote: a settled call's verdict, or the run's account of itself.
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

    /// Show a line the harness wrote: the gate's verdict on a settled call, what the run
    /// refused, or what an interrupt lost.
    ///
    /// Its breaks are spelled rather than kept: the view marks every row of a note, so a
    /// real break would mint a second marked row. `gate::line` escapes already; a
    /// provider-error note does not, being the vendor's string verbatim.
    pub fn note(&mut self, line: &str) {
        self.entries.push(Entry {
            kind: Kind::Note,
            text: printable(line).replace('\n', "\\n"),
        });
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
/// Four sets, each bounded in its arm below. A denylist, for [`invisible`]'s reason.
/// ASCII `|` is excluded, having to survive a shell pipeline in prose — which is why the
/// gutter is box-drawing instead, a `|` joining across rows being font-dependent.
fn forgeable(c: char) -> bool {
    matches!(
        c,
        // Every Box Drawing codepoint with a vertical stroke and no horizontal one. What
        // draws a horizontal too is left alone, junctions and corners included: a `tree` or
        // a table is ordinary output, and the nub beside the stroke is a difference on
        // screen where a weight is not.
        GUTTER_MARK
        | '\u{2503}' | '\u{2506}' | '\u{2507}' | '\u{250a}' | '\u{250b}'
        | '\u{254e}' | '\u{254f}' | '\u{2551}'
        | '\u{2575}' | '\u{2577}' | '\u{2579}' | '\u{257b}' | '\u{257d}' | '\u{257f}'
        // The bracket, box-line and integral extensions, drawn to tile vertically.
        | '\u{239c}' | '\u{239f}' | '\u{23a2}' | '\u{23a5}' | '\u{23aa}' | '\u{23ae}'
        | '\u{23b8}' | '\u{23b9}' | '\u{23d0}'
        // Single-cell vertical strokes outside both ranges — an enumeration, not a scope:
        // Unicode's confusables data is not in the tree to derive one from (#276). Out on
        // `|`'s reasoning: U+1175 and U+4E28 are letters in running text, and a Block
        // Element wider than an eighth reads as filled area, its loss costing a sparkline.
        | '\u{00a6}' | '\u{01c0}' | '\u{01c1}' | '\u{05c0}' | '\u{2016}' | '\u{2223}'
        | '\u{2225}' | '\u{258f}' | '\u{2595}' | '\u{2758}' | '\u{fe31}' | '\u{fe32}'
        | '\u{fe33}' | '\u{ff5c}' | '\u{ffdc}' | '\u{ffe8}'
        // Combining marks drawing a vertical on their base, a space included (#280); the base
        // survives. Out: the obliques, a slash not being the mark, and on `|`'s reasoning the
        // centralization strokes and script signs such as U+0951, diacritics in running text.
        | '\u{030d}' | '\u{030e}' | '\u{0329}' | '\u{0348}' | '\u{20d2}' | '\u{20d3}'
        | '\u{20e6}'
    )
}

#[cfg(test)]
#[path = "transcript_tests.rs"]
mod tests;
