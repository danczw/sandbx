//! What the screen shows, folded from the event stream one event at a time.
//!
//! Nothing here renders a *requested* call: only a settled one has an outcome. What it does
//! hold is the one question the operator is being asked about a call, until it is answered,
//! and the one approved call being run, until it settles. Neither is an entry.

use sandbx_event::AgentEvent;
use sandbx_text::{invisible, line_separator};

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

/// Whether the model's reasoning is drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reasoning {
    /// Drawn as it streams, apart from the answer.
    Shown,
    /// Dropped as it arrives.
    Hidden,
}

/// One turn as the screen shows it.
pub struct Transcript {
    entries: Vec<Entry>,

    /// Whether reasoning was asked for; the API sends the delta regardless.
    reasoning: Reasoning,

    /// Rounds seen, counted from `Stop`: no event carries the turn's own bound.
    rounds: usize,

    /// The last figure reported for the prompt and for the output, `None` until one arrives.
    /// Held per field because the API omits either independently: a reported zero is a
    /// figure, and an absence must not take a shown one back off the screen. Not a sum:
    /// each is one request's, as `TurnOutcome::usage` is.
    tokens: Tokens,

    /// The rows of the question being asked of the operator, empty when there is none.
    /// Apart from `entries`: it is not part of the turn, and is gone once answered.
    question: Vec<String>,

    /// The approved call being run, `None` when there is none. Apart from `entries` for the
    /// question's reason, and for #169's: it is drawn while the call runs, and nothing of it
    /// is left to contradict a refusal that comes after approval.
    running: Option<String>,
}

/// The last token counts reported for a turn's requests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Tokens {
    pub(crate) input: Option<u32>,
    pub(crate) output: Option<u32>,
}

impl Transcript {
    /// Start one on the prompt that opened it.
    pub fn new(prompt: &str, reasoning: Reasoning) -> Self {
        Self {
            entries: vec![Entry {
                kind: Kind::Prompt,
                text: printable(prompt),
            }],
            reasoning,
            rounds: 0,
            tokens: Tokens::default(),
            question: Vec::new(),
            running: None,
        }
    }

    /// Fold one event in. A reasoning block and a redacted one are dropped, both carrying
    /// replay material that must not render.
    pub fn event(&mut self, event: &AgentEvent) {
        match event {
            AgentEvent::Text { delta } => self.append(delta, Kind::Answer),
            AgentEvent::Thinking { delta } if self.reasoning == Reasoning::Shown => {
                self.append(delta, Kind::Reasoning);
            }
            AgentEvent::Stop { .. } => self.rounds += 1,
            AgentEvent::Usage {
                input_tokens,
                output_tokens,
                ..
            } => {
                self.tokens.input = input_tokens.or(self.tokens.input);
                self.tokens.output = output_tokens.or(self.tokens.output);
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
    /// real break would mint a second marked row. `gate::line` and `error_line` spell
    /// already, `\` included, so this is a backstop and leaves `\` alone: spelling it
    /// again would double theirs.
    pub fn note(&mut self, line: &str) {
        self.entries.push(Entry {
            kind: Kind::Note,
            text: spelled(line),
        });
    }

    /// Show the question the operator is being asked, one row per line, replacing any that
    /// was showing.
    ///
    /// Rows are stripped and spelled as a [`note`](Self::note) is, and the view marks every
    /// one: a line carrying the model's own words, a path or a command, would otherwise draw
    /// a row of the question that sandbx never wrote. The caller decides what is asked.
    pub fn ask(&mut self, lines: &[&str]) {
        self.question = lines.iter().map(|line| spelled(line)).collect();
    }

    /// Take the question down: the call has its answer.
    pub fn answered(&mut self) {
        self.question.clear();
    }

    /// Show the call being run, replacing any that was showing: the gate approved it, which
    /// is not a claim that it ran, and the view says no more than that it is under way.
    ///
    /// Stripped and spelled as a [`note`](Self::note) is, the command being the model's.
    pub fn run(&mut self, call: &str) {
        self.running = Some(spelled(call));
    }

    /// Take the running call down: it ended, however it ended. The line saying how is a
    /// [`note`](Self::note), and the caller makes both changes together.
    pub fn ended(&mut self) {
        self.running = None;
    }

    pub(crate) fn running(&self) -> Option<&str> {
        self.running.as_deref()
    }

    pub(crate) fn question(&self) -> &[String] {
        &self.question
    }

    pub(crate) fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub(crate) fn rounds(&self) -> usize {
        self.rounds
    }

    pub(crate) fn tokens(&self) -> Tokens {
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

/// One line of the harness's own, as [`Transcript::note`] shows it: [`printable`], with a
/// break spelled rather than kept, so the view's mark on a row cannot be minted a second
/// time. The one place a line carrying the model's words is made safe to mark.
fn spelled(line: &str) -> String {
    printable(line).replace('\n', "\\n")
}

/// Model-chosen text as it may be written to a cell. ratatui writes a cell's content
/// verbatim, so an escape sequence in an answer would rewrite the screen; replaced with
/// U+FFFD rather than dropped, since a dropped string reads as plausible prose. `\n`
/// survives as the view's split point, and U+2028 and U+2029 become one; a tab becomes
/// spaces, nothing else rendering a cell that holds one. [`GUTTER_MARK`] gets the same
/// replacement: the view draws it to mark a row as sandbx's, so text carrying it could
/// forge that claim.
fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());

    for c in text.chars() {
        match c {
            '\n' => out.push('\n'),
            c if line_separator(c) => out.push('\n'),
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
