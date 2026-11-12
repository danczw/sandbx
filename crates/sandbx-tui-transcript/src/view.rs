//! The layout: the transcript, the question being asked of the operator under it, and a
//! one-line status bar.
//!
//! Draws state and reads none, so a test renders into a `TestBackend` and asserts on cells
//! rather than on a running terminal.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Paragraph, Wrap};

use crate::transcript::{Kind, Tokens, Transcript};

/// The character that says sandbx wrote a row, and that no entry's text may draw. Not
/// ASCII: `|` or `>` is plausible in prose, and stripping either would mangle shell
/// pipelines. Draw, not contain — `transcript::forgeable` strips the confusables too.
pub(crate) const GUTTER_MARK: char = '│';

/// [`GUTTER_MARK`] as it is drawn: the mark, then the space separating it from the row.
const GUTTER: &str = "│ ";

/// Draw one frame: the whole transcript, tail-aligned, the question under it when one is
/// being asked or else the call being run, and the status bar under that.
///
/// The question takes its rows from the transcript and never the other way round. In a pane
/// too short for all of it, its middle goes and a marked row stands in: the first rows name
/// the call and the last say what the keys do, and a question missing either cannot be
/// answered knowingly. The running call is one row, clipped where the pane is short.
pub fn draw(frame: &mut Frame, transcript: &Transcript) {
    let area = frame.area();

    let question = question(transcript);
    // Never both: the gate takes the question down before it approves the call.
    let running = if question.is_none() {
        running(transcript)
    } else {
        None
    };
    let asked = question
        .as_ref()
        .or(running.as_ref())
        .map_or(0, |dock| dock.line_count(area.width));
    // The bar keeps its row.
    let shown = asked.min(usize::from(area.height.saturating_sub(1)));
    let [body, dock, bar] = Layout::vertical([
        Constraint::Min(0),
        Constraint::Length(u16::try_from(shown).unwrap_or(u16::MAX)),
        Constraint::Length(1),
    ])
    .areas(area);

    let paragraph = Paragraph::new(text(transcript)).wrap(Wrap { trim: false });

    // Auto-follow is measured after wrapping, not counted off entries: a wrapped answer has
    // more rows than newlines, and scrolling by the smaller figure strands the tail off-screen.
    let rows = paragraph.line_count(body.width);
    let scroll = u16::try_from(rows.saturating_sub(usize::from(body.height))).unwrap_or(u16::MAX);

    frame.render_widget(paragraph.scroll((scroll, 0)), body);
    if let Some(question) = question {
        if asked <= shown {
            frame.render_widget(question, dock);
        } else {
            cut_question(frame, transcript.question(), dock);
        }
    }
    if let Some(running) = running {
        frame.render_widget(running, dock);
    }
    frame.render_widget(status(transcript), bar);
}

/// Whether a pane of `width` by `height` can show the question being asked well enough to
/// answer it: whole, or cut to a head row, the mark and the choices. True where none is asked.
///
/// For a caller about to wait on keys: a question the pane cannot show is one the operator
/// would answer blind, and [`draw`] shows what it can regardless.
pub fn question_fits(transcript: &Transcript, width: u16, height: u16) -> bool {
    let Some(question) = question(transcript) else {
        return true;
    };

    let room = usize::from(height.saturating_sub(1));
    if question.line_count(width) <= room {
        return true;
    }

    let Some(choices) = transcript.question().last() else {
        return true;
    };
    // A head row, the mark, and the choices however they wrap.
    room >= marked(choices).line_count(width) + 2
}

/// A question that does not fit `dock`: its head, a row marking the cut, and its last row.
///
/// No blank row above it, that being the first thing to go. The last row is kept whole,
/// however it wraps. Where not even one head row would fit beside it, the last rows alone
/// are kept, as a transcript's are.
fn cut_question(frame: &mut Frame, rows: &[String], dock: Rect) {
    let Some((choices, head)) = rows.split_last() else {
        return;
    };

    let tail = marked(choices);
    let tail_rows = u16::try_from(tail.line_count(dock.width)).unwrap_or(u16::MAX);
    let head_rows = dock.height.saturating_sub(tail_rows.saturating_add(1));

    if head_rows == 0 {
        let all = question_paragraph(rows, true);
        let cut = all
            .line_count(dock.width)
            .saturating_sub(usize::from(dock.height));
        let cut = u16::try_from(cut).unwrap_or(u16::MAX);
        frame.render_widget(all.scroll((cut, 0)), dock);
        return;
    }

    let [top, mark, bottom] = Layout::vertical([
        Constraint::Length(head_rows),
        Constraint::Length(1),
        Constraint::Length(tail_rows),
    ])
    .areas(dock);

    frame.render_widget(question_paragraph(head, false), top);
    frame.render_widget(marked("…"), mark);
    frame.render_widget(tail, bottom);
}

/// The transcript as the screen drew it, unstyled, for a terminal the screen has given
/// back: the alternate screen takes every row with it, the answer among them.
pub fn plain(transcript: &Transcript) -> String {
    let mut out = String::new();

    for (_, row) in rows(transcript) {
        out.push_str(&row);
        out.push('\n');
    }

    out
}

/// The question being asked, on a blank row of its own and then [`GUTTER`]ed rows, or `None`
/// where nothing is asked. The mark is the only thing here an answer cannot draw, which is
/// why it is a mark and not a rule: an answer containing one could draw a boundary.
fn question(transcript: &Transcript) -> Option<Paragraph<'static>> {
    let rows = transcript.question();
    if rows.is_empty() {
        return None;
    }

    Some(question_paragraph(rows, true))
}

/// The call being run, on one [`GUTTER`]ed row in the gate's grammar, or `None` where none
/// is. The mark is why the command, which is the model's, cannot pass as sandbx's own words.
/// "Running" is all it claims: the call may still be refused after approval, and the row is
/// gone by then, so no entry is left to say otherwise.
fn running(transcript: &Transcript) -> Option<Paragraph<'static>> {
    let call = transcript.running()?;

    Some(marked(&format!("sandbx: {call} — running")))
}

/// `rows` as marked lines, under a blank row where `spaced`.
fn question_paragraph(rows: &[String], spaced: bool) -> Paragraph<'static> {
    let blank = spaced.then(Line::default);
    let lines: Vec<Line<'static>> = blank
        .into_iter()
        .chain(rows.iter().map(|row| marked_line(row)))
        .collect();

    Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false })
}

fn marked(row: &str) -> Paragraph<'static> {
    Paragraph::new(marked_line(row)).wrap(Wrap { trim: false })
}

fn marked_line(row: &str) -> Line<'static> {
    Line::from(Span::styled(
        format!("{GUTTER}{row}"),
        Style::new().add_modifier(Modifier::BOLD),
    ))
}

/// The transcript as rows, one blank row between entries.
fn text(transcript: &Transcript) -> Text<'static> {
    Text::from(
        rows(transcript)
            .map(|(kind, row)| match kind {
                Some(kind) => Line::from(Span::styled(row, style(kind))),
                None => Line::default(),
            })
            .collect::<Vec<_>>(),
    )
}

/// Every row with its gutter, and the kind it is styled as; `None` for the blank row between
/// two entries. One builder for both renderings, so [`plain`] cannot lose the gutter.
fn rows(transcript: &Transcript) -> impl Iterator<Item = (Option<Kind>, String)> {
    transcript
        .entries()
        .iter()
        .enumerate()
        .flat_map(|(at, entry)| {
            let gap = (at > 0).then(|| (None, String::new()));
            let body = entry
                .text
                .split('\n')
                .enumerate()
                .map(|(n, row)| (Some(entry.kind), format!("{}{row}", gutter(entry.kind, n))));

            gap.into_iter().chain(body)
        })
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
fn status(transcript: &Transcript) -> Paragraph<'static> {
    let mut fields = vec![format!("rounds {}", transcript.rounds())];

    // Each is absent until reported, never a zero: `0 in` would read as a turn that sent
    // nothing rather than one whose count hasn't arrived yet.
    let Tokens { input, output } = transcript.tokens();
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

    fields.push("ctrl-c interrupts".to_string());

    Paragraph::new(Line::from(fields.join(" · ")))
        .style(Style::new().add_modifier(Modifier::REVERSED))
}

#[cfg(test)]
#[path = "view_tests.rs"]
mod tests;
