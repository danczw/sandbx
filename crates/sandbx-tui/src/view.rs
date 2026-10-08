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

/// What the status bar says the operator can do now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hint {
    /// The turn is streaming, and a key can still stop it.
    Running,
    /// The turn is over and the screen is held so its last rounds can be read.
    Done,
}

/// Draw one frame: the whole transcript, tail-aligned, and the status bar under it.
pub(crate) fn draw(frame: &mut Frame, transcript: &Transcript, hint: Hint) {
    let [body, bar] =
        Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(frame.area());

    let paragraph = Paragraph::new(text(transcript)).wrap(Wrap { trim: false });

    // Auto-follow, measured after wrapping rather than counted off the entries: a wrapped
    // answer occupies more rows than it has newlines, and scrolling by the smaller figure
    // holds the tail off the screen exactly when there is most of it to read.
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
            let row = match (entry.kind, n) {
                (Kind::Prompt, 0) => format!("> {row}"),
                _ => row.to_string(),
            };
            rows.push(Line::from(Span::styled(row, style)));
        }
    }

    Text::from(rows)
}

/// How one kind of entry is set apart from the model's answer.
///
/// Modifiers rather than colours: a reasoning line and a refusal differ by weight on a
/// terminal with no palette, where a colour would land as the default foreground and make
/// the two read alike.
fn style(kind: Kind) -> Style {
    match kind {
        Kind::Prompt => Style::new().add_modifier(Modifier::BOLD),
        Kind::Answer => Style::new(),
        Kind::Reasoning => Style::new().add_modifier(Modifier::DIM | Modifier::ITALIC),
        Kind::Call | Kind::Note => Style::new().add_modifier(Modifier::BOLD | Modifier::DIM),
    }
}

/// The status bar: what the turn has spent, and what a key does.
fn status(transcript: &Transcript, hint: Hint) -> Paragraph<'static> {
    let mut fields = vec![format!("rounds {}", transcript.rounds())];

    // Each absent until the provider reports it, never a zero: "0 in" would read as a turn
    // that sent nothing rather than one whose count has not arrived. Separately, the API
    // omits either one.
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

    fields.push(
        match hint {
            Hint::Running => "ctrl-c interrupts",
            Hint::Done => "any key leaves",
        }
        .to_string(),
    );

    Paragraph::new(Line::from(fields.join(" · ")))
        .style(Style::new().add_modifier(Modifier::REVERSED))
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use sandbx_providers::AgentEvent;

    use super::*;

    /// Render `transcript` at that size and read the cells back as rows of text.
    fn rows(transcript: &Transcript, hint: Hint, width: u16, height: u16) -> Vec<String> {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test backend");
        terminal
            .draw(|frame| draw(frame, transcript, hint))
            .expect("draw");

        let buffer = terminal.backend().buffer().clone();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect()
    }

    fn turn(answer: &str) -> Transcript {
        let mut transcript = Transcript::new("what is here?", false);
        transcript.event(&AgentEvent::Text {
            delta: answer.to_string(),
        });
        transcript
    }

    #[test]
    fn the_prompt_the_answer_and_the_hint_are_all_on_screen() {
        let rows = rows(&turn("three files"), Hint::Running, 40, 6);

        assert_eq!(rows[0], "> what is here?");
        assert_eq!(rows[2], "three files");
        assert_eq!(rows[5], "rounds 0 · ctrl-c interrupts");
    }

    #[test]
    fn the_status_bar_reports_usage_once_it_arrives() {
        let mut transcript = turn("three files");
        transcript.event(&AgentEvent::Stop {
            reason: sandbx_providers::StopReason::EndTurn,
        });
        transcript.event(&AgentEvent::Usage {
            input_tokens: Some(1200),
            output_tokens: Some(64),
            cache_write_tokens: None,
            cache_read_tokens: None,
        });

        let rows = rows(&transcript, Hint::Done, 48, 6);
        assert_eq!(rows[5], "rounds 1 · 1200 in / 64 out · any key leaves");
    }

    /// A truncated line is a line an operator cannot recover: there is no scroll key and no
    /// scrollback behind the alternate screen.
    #[test]
    fn a_line_wider_than_the_pane_wraps_rather_than_truncating() {
        let transcript = turn("alpha bravo charlie delta echo");
        let rows = rows(&transcript, Hint::Running, 16, 8);

        let body = rows[2..5].join("|");
        assert_eq!(body, "alpha bravo|charlie delta|echo");
    }

    /// The tail is what a streaming turn is read from, so a transcript past the pane's
    /// height scrolls rather than stopping at the top.
    #[test]
    fn a_transcript_past_the_pane_shows_its_tail() {
        let transcript = turn("one\ntwo\nthree\nfour\nfive");

        // Non-vacuous: at a height that fits, the prompt is the first row — so its absence
        // below is the scroll and not a prompt that never rendered.
        let roomy = rows(&transcript, Hint::Running, 20, 10);
        assert_eq!(roomy[0], "> what is here?");
        assert_eq!(roomy[6], "five");

        let cramped = rows(&transcript, Hint::Running, 20, 4);
        assert_eq!(cramped[2], "five", "{cramped:?}");
        assert!(
            !cramped.iter().any(|row| row.contains("what is here?")),
            "{cramped:?}"
        );
    }

    /// Entries are divided by a blank row and not by a rule, so a model answer containing
    /// one cannot be read as the boundary between two entries.
    #[test]
    fn a_call_is_divided_from_the_text_around_it_by_a_blank_row() {
        let mut transcript = turn("looking");
        transcript.call("sandbx: ls /work — ran");
        transcript.event(&AgentEvent::Text {
            delta: "three files".to_string(),
        });

        let rows = rows(&transcript, Hint::Running, 40, 9);
        assert_eq!(
            rows[..7],
            [
                "> what is here?",
                "",
                "looking",
                "",
                "sandbx: ls /work — ran",
                "",
                "three files",
            ]
        );
    }
}
