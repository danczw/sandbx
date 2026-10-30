//! The terminal the turn is drawn on, and putting it back.
//!
//! Measured by `Measured`, never by crossterm's `terminal::size`, which can fork `tput` (#269).
//!
//! Model-chosen text is stripped in [`sandbx_tui_transcript`], not at the caller, because
//! the screen is what an escape sequence inside it would rewrite.

use std::io::{self, Stdout, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::panic;

use ratatui::Terminal;
use ratatui::backend::{Backend, ClearType, CrosstermBackend, WindowSize};
use ratatui::buffer::Cell;
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{EnterAlternateScreen, enable_raw_mode};
use ratatui::layout::{Position, Rect, Size};
use sandbx_tui_transcript::{Hint, draw};

/// With it: [`Transcript::new`] takes one.
pub use sandbx_tui_transcript::Reasoning;
/// Re-exported, not left to the caller: every entry point here takes or returns one (#352).
pub use sandbx_tui_transcript::Transcript;

/// The alternate screen one turn is drawn on, and its transcript; restored when this drops.
pub struct Screen {
    terminal: Terminal<Measured<Stdout>>,

    /// The first draw failure, `observe` having nowhere to return one. The first and not the
    /// last: a closed stdout fails once per event, and the last says only that it was gone.
    failed: Option<io::Error>,

    transcript: Transcript,
}

impl Screen {
    /// Take the terminal: raw mode on, alternate screen entered. Raw mode makes ctrl-c reach
    /// `sandbx_tui_input::Keys` as a key, not a `SIGINT` killing the process with the screen up.
    pub fn enter(transcript: Transcript) -> io::Result<Self> {
        // First, before anything fallible, so a panic in `take_terminal` is covered too.
        // `try_restore` and not `restore`: inside a hook its `eprintln!` to the descriptor
        // that just died would be a panic while panicking, which aborts (#264).
        let reported = panic::take_hook();
        panic::set_hook(Box::new(move |panicked| {
            let _ = ratatui::try_restore();
            reported(panicked);
        }));

        let terminal = take_terminal().inspect_err(|_| {
            // `try_restore`, for the reason `Screen::drop` gives: a terminal that cannot be
            // entered may be one that cannot be reported to either.
            let _ = ratatui::try_restore();
        })?;

        Ok(Self {
            terminal,
            failed: None,
            transcript,
        })
    }

    /// Apply `change` to the transcript, then repaint while the turn still runs. The change
    /// is applied even once a draw has failed, so the transcript stays whole.
    pub fn paint(&mut self, change: impl FnOnce(&mut Transcript)) {
        change(&mut self.transcript);
        self.draw(Hint::Running);
    }

    /// Apply `change`, then repaint every cell for the finished turn: ratatui flushes only the
    /// diff between its buffers, so a cell stderr wrote under the alternate screen survives
    /// unless the back buffer is discarded. By `resize`, never `Terminal::clear`, whose cursor
    /// query takes crossterm's one reader lock that `sandbx_tui_input::Keys` may hold, or races
    /// it for the reply. A same-size resize asks the terminal nothing only on the fullscreen
    /// viewport `Terminal::new` gives; an inline one recomputes its origin from the cursor,
    /// which is that query again.
    pub fn finish(&mut self, change: impl FnOnce(&mut Transcript)) {
        change(&mut self.transcript);
        if self.failed.is_some() {
            return;
        }

        match cleared(&mut self.terminal) {
            Ok(()) => self.draw(Hint::Done),
            Err(error) => self.failed = Some(error),
        }
    }

    fn draw(&mut self, hint: Hint) {
        if self.failed.is_some() {
            return;
        }

        let drawn = self
            .terminal
            .draw(|frame| draw(frame, &self.transcript, hint));
        if let Err(error) = drawn {
            self.failed = Some(error);
        }
    }

    /// The draw failure that stopped the screen updating, if one did. Taken, so a caller
    /// reports it once — and it must: everything after it happened off-screen, and a turn
    /// whose tool calls nobody saw was not watched.
    pub fn failure(&mut self) -> Option<io::Error> {
        self.failed.take()
    }
}

/// Every cell discarded and the screen cleared, at the size the window is now.
///
/// Fails, and writes nothing, on a window [`Measured`] cannot read.
fn cleared<B: Backend>(terminal: &mut Terminal<B>) -> Result<(), B::Error> {
    terminal.resize(Rect::from(terminal.size()?))
}

/// `ratatui::try_init`'s three fallible statements, without the hook it installs first, and
/// with [`Measured`] for its backend.
///
/// Reproduced, not called: that hook restores with `restore` and goes in first, so
/// replacing it after still leaves a window where the aborting one is in force (#270).
/// Copied from `init.rs:397-403` of ratatui `=0.30.2` — exactly pinned, so a bump re-reads
/// that function rather than assuming it still says this.
fn take_terminal() -> io::Result<Terminal<Measured<Stdout>>> {
    // Raw mode before the alt screen, so a failed second step leaves the first in force.
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    Terminal::new(Measured::new(io::stdout())?)
}

/// crossterm's backend, with the window read off the descriptor it draws to.
///
/// A window that cannot be read fails the size, which every draw, clear and redraw asks
/// for before it writes: on a hung-up terminal nothing is drawn, and nothing forks (#269).
pub(crate) struct Measured<W: Write> {
    backend: CrosstermBackend<W>,
    /// A dup of the drawn descriptor: ratatui hides the writer, and a hangup reaches every dup.
    out: OwnedFd,
    /// Set as the screen goes, so a cursor that cannot be shown reads as shown. Not always: a
    /// frame that set a cursor would reach `show_cursor` from a draw, and that failure belongs
    /// in `failed`.
    quiet: bool,
}

impl<W: Write> Measured<W> {
    pub(crate) fn new(writer: W) -> io::Result<Self>
    where
        W: AsFd,
    {
        let out = writer.as_fd().try_clone_to_owned()?;

        // The one `CrosstermBackend::new`, whose own size would be crossterm's. See
        // `clippy.toml`.
        #[allow(clippy::disallowed_methods)]
        let backend = CrosstermBackend::new(writer);

        Ok(Self {
            backend,
            out,
            quiet: false,
        })
    }

    /// `TIOCGWINSZ` on the descriptor drawn to, and its error as it came: no `tput` behind
    /// it, and not `/dev/tty`, which crossterm reads first and need not be this screen.
    fn window(&self) -> io::Result<rustix::termios::Winsize> {
        Ok(rustix::termios::tcgetwinsize(&self.out)?)
    }
}

impl<W: Write> Backend for Measured<W> {
    type Error = io::Error;

    fn draw<'a, I>(&mut self, content: I) -> io::Result<()>
    where
        I: Iterator<Item = (u16, u16, &'a Cell)>,
    {
        self.backend.draw(content)
    }

    fn append_lines(&mut self, n: u16) -> io::Result<()> {
        self.backend.append_lines(n)
    }

    fn hide_cursor(&mut self) -> io::Result<()> {
        self.backend.hide_cursor()
    }

    /// `Terminal::show_cursor` clears the flag `Terminal::drop` reads only on `Ok`, and that
    /// `Drop` `eprintln!`s on `Err`. Once quiet nothing reads the cursor again.
    fn show_cursor(&mut self) -> io::Result<()> {
        match self.backend.show_cursor() {
            Err(_) if self.quiet => Ok(()),
            shown => shown,
        }
    }

    fn get_cursor_position(&mut self) -> io::Result<Position> {
        self.backend.get_cursor_position()
    }

    fn set_cursor_position<P: Into<Position>>(&mut self, position: P) -> io::Result<()> {
        self.backend.set_cursor_position(position)
    }

    fn clear(&mut self) -> io::Result<()> {
        self.backend.clear()
    }

    fn clear_region(&mut self, clear_type: ClearType) -> io::Result<()> {
        self.backend.clear_region(clear_type)
    }

    fn size(&self) -> io::Result<Size> {
        let window = self.window()?;
        Ok(Size::new(window.ws_col, window.ws_row))
    }

    fn window_size(&mut self) -> io::Result<WindowSize> {
        let window = self.window()?;
        Ok(WindowSize {
            columns_rows: Size::new(window.ws_col, window.ws_row),
            pixels: Size::new(window.ws_xpixel, window.ws_ypixel),
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        Backend::flush(&mut self.backend)
    }
}

impl Drop for Screen {
    /// Leave raw mode and the alternate screen, whatever the turn did.
    ///
    /// `Drop`, not a method: an unwinding panic must still restore the terminal, which
    /// [`Screen::enter`]'s hook covers only earlier. Neither covers `SIGKILL`.
    ///
    /// `try_restore` and not `restore`: `restore` reports a failed `tcsetattr` with
    /// `eprintln!` to the descriptor that just died, and that panic inside an unwinding
    /// `Drop` aborts (#264). `Terminal::drop`, which runs next, has the same `eprintln!` for
    /// a cursor it cannot show; quieting `Measured` first is what keeps it from reaching it.
    fn drop(&mut self) {
        // Ignored: there is nothing left to report a terminal that stopped answering to.
        let _ = ratatui::try_restore();
        self.terminal.backend_mut().quiet = true;
    }
}

#[cfg(test)]
#[path = "screen_tests.rs"]
mod tests;
