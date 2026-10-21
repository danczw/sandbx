//! The terminal the turn is drawn on, and putting it back.
//!
//! Measured by [`Measured`] and never by crossterm, whose `terminal::size` forks `tput` from
//! this unsandboxed process when the window cannot be read — every draw on a hung-up terminal.

use std::io::{self, Stdout, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::panic::AssertUnwindSafe;

use ratatui::Terminal;
use ratatui::backend::{Backend, ClearType, CrosstermBackend, WindowSize};
use ratatui::buffer::Cell;
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{EnterAlternateScreen, enable_raw_mode};
use ratatui::layout::{Position, Rect, Size};

use crate::transcript::Transcript;
use crate::view::{self, Hint};

/// The alternate screen one turn is drawn on, restored when this drops.
pub struct Screen {
    /// `Option` only so [`Screen::drop`] can take it: `Terminal`'s own `Drop` can panic,
    /// and containing that needs the value moved rather than borrowed.
    terminal: Option<Terminal<Measured<Stdout>>>,

    /// The first draw failure, `observe` having nowhere to return one. The first and not the
    /// last: a closed stdout fails once per event, and the last says only that it was gone.
    failed: Option<io::Error>,
}

impl Screen {
    /// Take the terminal: raw mode on, alternate screen entered. Raw mode makes ctrl-c reach
    /// [`Keys`](crate::Keys) as a key, not a `SIGINT` killing the process with the screen up.
    pub fn enter() -> io::Result<Self> {
        // First, before anything fallible, so a panic in `take_terminal` is covered too.
        // `try_restore` and not `restore`: inside a hook its `eprintln!` to the descriptor
        // that just died would be a panic while panicking, which aborts (#264).
        let reported = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |panicked| {
            let _ = ratatui::try_restore();
            reported(panicked);
        }));

        let terminal = take_terminal().inspect_err(|_| {
            // `try_restore`, for the reason `Screen::drop` gives: a terminal that cannot be
            // entered may be one that cannot be reported to either.
            let _ = ratatui::try_restore();
        })?;

        Ok(Self {
            terminal: Some(terminal),
            failed: None,
        })
    }

    /// The terminal, which a live `Screen` always holds — only [`Screen::drop`] takes it.
    fn terminal(&mut self) -> &mut Terminal<Measured<Stdout>> {
        self.terminal
            .as_mut()
            .expect("a screen holds its terminal until it drops")
    }

    /// Repaint the whole screen from `transcript`.
    pub fn draw(&mut self, transcript: &Transcript, hint: Hint) {
        if self.failed.is_some() {
            return;
        }

        if let Err(error) = self
            .terminal()
            .draw(|frame| view::draw(frame, transcript, hint))
        {
            self.failed = Some(error);
        }
    }

    /// Repaint every cell, not only the ones the transcript changed. ratatui only flushes the
    /// diff between its two buffers; a cell stderr wrote (unredirected by the alternate screen)
    /// is never rewritten, so discarding the back buffer is the only fix. `resize`, never
    /// `Terminal::clear`: `clear`'s cursor query takes crossterm's one reader lock, which
    /// [`Keys`](crate::Keys) may be holding — and if it wins the lock instead, it races the
    /// reader for the reply bytes. Resizing to the size already in force asks the terminal
    /// nothing only on the fullscreen viewport `Terminal::new` gives: an inline one recomputes
    /// its origin from the cursor, which is that query back again.
    pub fn redraw(&mut self, transcript: &Transcript, hint: Hint) {
        if self.failed.is_some() {
            return;
        }

        match cleared(self.terminal()) {
            Ok(()) => self.draw(transcript, hint),
            Err(error) => self.failed = Some(error),
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
    let area = Rect::from(terminal.size()?);
    terminal.resize(area)
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
    /// A duplicate of the descriptor `backend` writes to: ratatui hands the writer back only
    /// behind an unstable feature, and a hangup reaches every descriptor for the file alike.
    out: OwnedFd,
}

impl<W: Write> Measured<W> {
    pub(crate) fn new(out: W) -> io::Result<Self>
    where
        W: AsFd,
    {
        let duplicate = out.as_fd().try_clone_to_owned()?;

        // The one `CrosstermBackend::new`, whose own size would be crossterm's. See
        // `clippy.toml`.
        #[allow(clippy::disallowed_methods)]
        let backend = CrosstermBackend::new(out);

        Ok(Self {
            backend,
            out: duplicate,
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

    fn show_cursor(&mut self) -> io::Result<()> {
        self.backend.show_cursor()
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
    /// `Drop` aborts (#264).
    fn drop(&mut self) {
        // Ignored: there is nothing left to report a terminal that stopped answering to.
        let _ = ratatui::try_restore();

        if let Some(terminal) = self.terminal.take() {
            // `Terminal::drop` `eprintln!`s when it cannot show the cursor a draw hid, which
            // is the same panic from inside this `Drop`. Contained rather than prevented:
            // `show_cursor` clears the flag `Drop` reads only once the backend accepted it,
            // which a dead one never will.
            let _ = std::panic::catch_unwind(AssertUnwindSafe(move || drop(terminal)));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell as Shared;
    use std::fs::File;
    use std::rc::Rc;

    use nix::errno::Errno;

    use super::*;
    use crate::input::tests::{WINDOW, pty};

    /// A pty slave, counting the writes that reach it: a draw that was attempted wrote.
    struct Counted {
        pty: File,
        writes: Rc<Shared<usize>>,
    }

    impl Write for Counted {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.writes.set(self.writes.get() + 1);
            self.pty.write(bytes)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.pty.flush()
        }
    }

    impl AsFd for Counted {
        fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
            self.pty.as_fd()
        }
    }

    /// A terminal over a live pty, taken as `Screen::enter` takes stdout; the master whose
    /// drop hangs it up; and the count of writes that reached it.
    fn screen() -> (File, Terminal<Measured<Counted>>, Rc<Shared<usize>>) {
        let (master, slave) = pty();
        let writes = Rc::default();
        let counted = Counted {
            pty: slave,
            writes: Rc::clone(&writes),
        };

        let measured = Measured::new(counted).expect("a duplicate of the pty");
        let terminal = Terminal::new(measured).expect("a live pty is measured");

        (master, terminal, writes)
    }

    /// The pty's own `EIO` and not a size from anywhere else, `tput`'s included.
    fn assert_unmeasured(failed: io::Result<()>) {
        let error = failed.expect_err("a hung-up pty was drawn on");
        assert_eq!(error.raw_os_error(), Some(Errno::EIO as i32), "{error}");
    }

    /// The whole of #269: a draw on a hung-up terminal fails at the size, before it writes.
    #[test]
    fn a_hung_up_terminal_is_not_drawn_on() {
        let (master, mut terminal, writes) = screen();
        let transcript = Transcript::new("a prompt", false);
        drop(master);

        let drawn = terminal.draw(|frame| view::draw(frame, &transcript, Hint::Running));

        assert_unmeasured(drawn.map(drop));
        assert_eq!(writes.get(), 0, "the draw was attempted");
    }

    /// And `redraw`'s clear, which asks for the size itself rather than through a draw.
    #[test]
    fn a_hung_up_terminal_is_not_cleared() {
        let (master, mut terminal, writes) = screen();
        drop(master);

        assert_unmeasured(cleared(&mut terminal));
        assert_eq!(writes.get(), 0, "the clear was attempted");
    }

    /// The pair: a live pty is measured off its own descriptor, then cleared and drawn on,
    /// so the two above are the hangup and not a backend that refuses everything.
    #[test]
    fn a_live_terminal_is_drawn_at_its_own_size() {
        let (_master, mut terminal, writes) = screen();
        let transcript = Transcript::new("a prompt", false);

        let size = terminal.size().expect("a live pty is measured");
        assert_eq!((size.width, size.height), WINDOW);

        cleared(&mut terminal).expect("a live pty is cleared");
        terminal
            .draw(|frame| view::draw(frame, &transcript, Hint::Running))
            .expect("a live pty is drawn on");
        assert!(writes.get() > 0, "nothing reached a live pty");
    }
}
