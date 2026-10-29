//! The layout: the transcript over a one-line status bar.
//!
//! Draws state and reads none, so a test renders into a `TestBackend` and asserts on cells
//! rather than on a running terminal.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Paragraph, Wrap};

use crate::transcript::{Kind, Transcript};

/// The character that says sandbx wrote a row, and that no entry's text may draw. Not
/// ASCII: `|` or `>` is plausible in prose, and stripping either would mangle shell
/// pipelines. Draw, not contain — `transcript::forgeable` strips the confusables too.
pub(crate) const GUTTER_MARK: char = '│';

/// [`GUTTER_MARK`] as it is drawn: the mark, then the space separating it from the row.
const GUTTER: &str = "│ ";

/// What the status bar says the operator can do now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hint {
    /// The turn is streaming, and a key can still stop it.
    Running,
    /// The turn is over and the screen is held so its last rounds can be read.
    Done,
}

/// Draw one frame: the whole transcript, tail-aligned, and the status bar under it.
pub fn draw(frame: &mut Frame, transcript: &Transcript, hint: Hint) {
    let [body, bar] =
        Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(frame.area());

    let paragraph = Paragraph::new(text(transcript)).wrap(Wrap { trim: false });

    // Auto-follow is measured after wrapping, not counted off entries: a wrapped answer has
    // more rows than newlines, and scrolling by the smaller figure strands the tail off-screen.
    let rows = paragraph.line_count(body.width);
    let scroll = u16::try_from(rows.saturating_sub(usize::from(body.height))).unwrap_or(u16::MAX);

    frame.render_widget(paragraph.scroll((scroll, 0)), body);
    frame.render_widget(status(transcript, hint), bar);
}

/// The transcript as rows, one blank row between entries.
fn text(transcript: &Transcript) -> Text<'static> {
    let mut rows: Vec<Line<'static>> = Vec::new();

    for entry in transcript.entries() {
        if !rows.is_empty() {
            rows.push(Line::default());
        }

        let style = style(entry.kind);
        for (n, row) in entry.text.split('\n').enumerate() {
            let row = format!("{}{row}", gutter(entry.kind, n));
            rows.push(Line::from(Span::styled(row, style)));
        }
    }

    Text::from(rows)
}

/// What marks row `n` of an entry as the harness speaking, or as something it was told.
/// [`GUTTER`] is the whole claim that sandbx wrote the row, drawn only here: [`Transcript`]
/// strips the mark and its confusables from entry text, or an answer with its own
/// `sandbx: bash … — ran` would render as a free-standing row in the gate's grammar —
/// modifiers don't help, a terminal dropping them renders a forged row and a real one alike.
/// Every row, not just the first, since a forged line can sit mid-entry — also why a break
/// inside a [`Kind::Note`] is spelled rather than kept.
/// Inline in the paragraph's text, not a separate column: survivable only because no entry
/// text can draw the mark, not because the column is defended — an area of its own would
/// retire the question.
fn gutter(kind: Kind, n: usize) -> &'static str {
    match (kind, n) {
        (Kind::Note, _) => GUTTER,
        (Kind::Prompt, 0) => "> ",
        // Aligned under the two above, so a row is read against them rather than measured.
        (Kind::Prompt | Kind::Answer | Kind::Reasoning, _) => "  ",
    }
}

/// How one kind of entry is set apart from the model's answer. Modifiers, not colours: on
/// a terminal with no palette a colour falls back to the default foreground, making a
/// reasoning line and a refusal read alike.
fn style(kind: Kind) -> Style {
    match kind {
        Kind::Prompt => Style::new().add_modifier(Modifier::BOLD),
        Kind::Answer => Style::new(),
        Kind::Reasoning => Style::new().add_modifier(Modifier::DIM | Modifier::ITALIC),
        Kind::Note => Style::new().add_modifier(Modifier::BOLD | Modifier::DIM),
    }
}

/// The status bar: what the turn has spent, and what a key does.
fn status(transcript: &Transcript, hint: Hint) -> Paragraph<'static> {
    let mut fields = vec![format!("rounds {}", transcript.rounds())];

    // Each is absent until reported, never a zero: `0 in` would read as a turn that sent
    // nothing rather than one whose count hasn't arrived yet.
    let (input, output) = transcript.tokens();
    let spend: Vec<String> = [
        input.map(|n| format!("{n} in")),
        output.map(|n| format!("{n} out")),
    ]
    .into_iter()
    .flatten()
    .collect();
    if !spend.is_empty() {
        fields.push(spend.join(" / "));
    }

    let hint = match hint {
        Hint::Running => "ctrl-c interrupts",
        Hint::Done => "any key leaves",
    };
    fields.push(hint.to_string());

    Paragraph::new(Line::from(fields.join(" · ")))
        .style(Style::new().add_modifier(Modifier::REVERSED))
}

#[cfg(test)]
#[path = "view_tests.rs"]
mod tests;
