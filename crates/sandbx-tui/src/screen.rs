//! The terminal the turn is drawn on, and putting it back.

use std::io;

use ratatui::DefaultTerminal;

use crate::transcript::Transcript;
use crate::view::{self, Hint};

/// The alternate screen one turn is drawn on, restored when this drops.
pub struct Screen {
    terminal: DefaultTerminal,

    /// The first draw failure, kept rather than returned.
    ///
    /// Drawing happens inside the turn's `observe`, which returns nothing, so a failure has
    /// nowhere to go until the turn ends. The first is kept and the rest are not attempted:
    /// a closed stdout fails once per event, and the last error says only that the screen
    /// was already gone.
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

    /// The draw failure that stopped the screen updating, if one did.
    ///
    /// Taken, so a caller reports it once. Worth reporting: everything after it happened
    /// off-screen, and a turn whose tool calls an operator never saw is not one they
    /// watched.
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
