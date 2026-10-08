//! The terminal the turn is drawn on, and putting it back.

use std::io;

use ratatui::DefaultTerminal;
use ratatui::layout::Rect;

use crate::transcript::Transcript;
use crate::view::{self, Hint};

/// The alternate screen one turn is drawn on, restored when this drops.
pub struct Screen {
    terminal: DefaultTerminal,

    /// The first draw failure, kept rather than returned.
    ///
    /// Drawing happens inside the turn's `observe`, which returns nothing, so a failure has
    /// nowhere to go until the turn ends. The first and not the last: a closed stdout fails
    /// once per event, and the last error says only that the screen was already gone.
    failed: Option<io::Error>,
}

impl Screen {
    /// Take the terminal: raw mode on, alternate screen entered.
    ///
    /// Raw mode is what makes an interrupt key reach [`Keys`](crate::Keys) at all — without
    /// it ctrl-c raises `SIGINT`, and the default handler kills the process with the
    /// alternate screen still on the operator's terminal.
    pub fn enter() -> io::Result<Self> {
        // Raw mode is enabled before the alternate screen is opened, so a failure at the
        // second step returns with the first still in force.
        let terminal = ratatui::try_init().inspect_err(|_| ratatui::restore())?;

        Ok(Self {
            terminal,
            failed: None,
        })
    }

    /// Repaint the whole screen from `transcript`.
    pub fn draw(&mut self, transcript: &Transcript, hint: Hint) {
        if self.failed.is_some() {
            return;
        }

        if let Err(error) = self
            .terminal
            .draw(|frame| view::draw(frame, transcript, hint))
        {
            self.failed = Some(error);
        }
    }

    /// Repaint every cell, not only the ones the transcript changed.
    ///
    /// ratatui flushes the difference between its own two buffers, so a cell something else
    /// wrote is never rewritten, and the newline with it scrolled the pane a row out of
    /// place. Stderr is that writer, the alternate screen not redirecting it, and discarding
    /// the last buffer is the only way back.
    ///
    /// `resize` and never `Terminal::clear`, which reads the cursor position: that is a DSR
    /// query answered through crossterm's one reader, and [`Keys`](crate::Keys) holds its lock
    /// parked in `event::read`, so the query times out and takes this repaint with it.
    /// Resizing to the size already in force clears the viewport and resets the back buffer,
    /// asking the terminal nothing.
    pub fn redraw(&mut self, transcript: &Transcript, hint: Hint) {
        if self.failed.is_some() {
            return;
        }

        let cleared = self
            .terminal
            .size()
            .map(Rect::from)
            .and_then(|area| self.terminal.resize(area));

        match cleared {
            Ok(()) => self.draw(transcript, hint),
            Err(error) => self.failed = Some(error),
        }
    }

    /// The draw failure that stopped the screen updating, if one did.
    ///
    /// Taken, so a caller reports it once. Worth reporting: everything after it happened
    /// off-screen, and a turn whose tool calls nobody saw was not watched.
    pub fn failure(&mut self) -> Option<io::Error> {
        self.failed.take()
    }
}

impl Drop for Screen {
    /// Leave raw mode and the alternate screen, whatever the turn did.
    ///
    /// `Drop` and not a method: a panic unwinding through the turn must still put the
    /// terminal back, and `try_init`'s own panic hook covers only an abort before this
    /// exists. `SIGKILL` is not covered by either.
    fn drop(&mut self) {
        ratatui::restore();
    }
}
