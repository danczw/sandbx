//! The terminal the turn is drawn on, and putting it back.

use std::io;
use std::panic::AssertUnwindSafe;

use ratatui::DefaultTerminal;
use ratatui::layout::Rect;

use crate::transcript::Transcript;
use crate::view::{self, Hint};

/// The alternate screen one turn is drawn on, restored when this drops.
pub struct Screen {
    /// `Option` only so [`Screen::drop`] can take it: `Terminal`'s own `Drop` can panic,
    /// and containing that needs the value moved rather than borrowed.
    terminal: Option<DefaultTerminal>,

    /// The first draw failure, `observe` having nowhere to return one. The first and not the
    /// last: a closed stdout fails once per event, and the last says only that it was gone.
    failed: Option<io::Error>,
}

impl Screen {
    /// Take the terminal: raw mode on, alternate screen entered. Raw mode makes ctrl-c reach
    /// [`Keys`](crate::Keys) as a key, not a `SIGINT` killing the process with the screen up.
    pub fn enter() -> io::Result<Self> {
        // Taken before `try_init`, which installs a hook chaining to whatever is in force:
        // this is the one to chain to once that hook is replaced below.
        let reported = std::panic::take_hook();

        // Raw mode before the alt screen, so a failed second step leaves the first in force.
        let entered = ratatui::try_init();

        // Replaced whether or not the terminal was entered, `try_init` installing its hook
        // before anything that can fail. ratatui's hook restores with `restore`, whose
        // `eprintln!` on a failed `tcsetattr` panics — and a panic raised inside the hook
        // is a panic while panicking, which aborts. This one cannot write (#264).
        std::panic::set_hook(Box::new(move |panicked| {
            let _ = ratatui::try_restore();
            reported(panicked);
        }));

        let terminal = entered.inspect_err(|_| {
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
    fn terminal(&mut self) -> &mut DefaultTerminal {
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
    /// reader for the reply bytes. Resizing to the size already in force
    /// asks the terminal nothing only on the fullscreen viewport `try_init` gives: an inline
    /// one recomputes its origin from the cursor, which is that query back again.
    pub fn redraw(&mut self, transcript: &Transcript, hint: Hint) {
        if self.failed.is_some() {
            return;
        }

        let cleared = self
            .terminal()
            .size()
            .map(Rect::from)
            .and_then(|area| self.terminal().resize(area));

        match cleared {
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

impl Drop for Screen {
    /// Leave raw mode and the alternate screen, whatever the turn did.
    ///
    /// `Drop`, not a method: an unwinding panic must still restore the terminal, which
    /// `try_init`'s hook covers only earlier. Neither covers `SIGKILL`.
    ///
    /// `try_restore` and not `restore`: on a terminal that hung up, `restore` reports the
    /// failed `tcsetattr` with `eprintln!` to the same dead descriptor and panics. Inside
    /// a `Drop` already unwinding, that is a panic while panicking, which aborts (#264).
    fn drop(&mut self) {
        // Ignored: there is nothing left to report a terminal that stopped answering to.
        let _ = ratatui::try_restore();

        if let Some(terminal) = self.terminal.take() {
            // `Terminal::drop` shows the cursor if a draw hid it and `eprintln!`s when it
            // cannot. On a hung-up terminal stderr is usually that same descriptor, so the
            // write fails and the macro panics — from inside this `Drop`, where it would
            // unwind past the code the turn earned. Contained rather than prevented:
            // `show_cursor` clears the flag `Drop` reads only once the backend accepted it,
            // which a dead one never will.
            let _ = std::panic::catch_unwind(AssertUnwindSafe(move || drop(terminal)));
        }
    }
}
