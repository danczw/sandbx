//! The key reader, and what the turn learns from it.

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use tokio::sync::watch;

/// What the reader has seen so far.
///
/// `stop` is sticky because a watch channel keeps only the latest value: an interrupt
/// followed quickly by any other key would otherwise be overwritten unread.
#[derive(Debug, Clone, Copy, Default)]
struct Seen {
    presses: u64,
    stop: bool,
}

/// The keys the operator presses, as the turn awaits them.
///
/// Start one only after [`Screen::enter`](crate::Screen::enter): without raw mode ctrl-c is
/// a signal rather than a key, and nothing here ever sees it.
pub struct Keys {
    seen: watch::Receiver<Seen>,
}

impl Keys {
    /// Start reading keys on a thread of their own.
    ///
    /// The thread outlives the turn: `event::read` cannot be cancelled, so it sits in one
    /// until the next key arrives or the process ends. It holds no state and draws nothing,
    /// so what it outlives it cannot disturb.
    pub fn listen() -> Self {
        let (sender, seen) = watch::channel(Seen::default());
        std::thread::spawn(move || read(&sender));

        Self { seen }
    }

    /// Resolves on the first key that means "stop this turn".
    ///
    /// Never on a reader that has gone: a closed channel is a terminal that can no longer
    /// be read, and resolving on it would end a turn nobody asked to end.
    pub async fn stop(&mut self) {
        loop {
            if self.seen.borrow_and_update().stop {
                return;
            }

            if self.seen.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }

    /// Resolves on the next key of any kind, for holding a finished screen.
    ///
    /// Resolves at once on a reader that has gone — the opposite of [`stop`](Self::stop)
    /// and for the same reason: with no key able to arrive, waiting for one would hold the
    /// alternate screen until the process was killed.
    pub async fn press(&mut self) {
        self.seen.mark_unchanged();
        let _ = self.seen.changed().await;
    }
}

/// Read keys until the channel closes or the terminal stops answering.
fn read(sender: &watch::Sender<Seen>) {
    let mut seen = Seen::default();

    loop {
        match event::read() {
            // `Press` alone: Windows reports a release for every key, and counting both
            // would read one keystroke as two.
            Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => {
                seen.presses += 1;
                seen.stop |= interrupts(key);

                if sender.send(seen).is_err() {
                    return;
                }
            }
            // Resize, mouse, paste and focus: nothing here acts on them, and a redraw is
            // driven by the event stream instead.
            Ok(_) => {}
            // Not retried: a read fails because the descriptor is gone, and looping on it
            // spins a thread at full speed for the rest of the run.
            Err(_) => return,
        }
    }
}

/// Whether `key` means "stop this turn".
///
/// Ctrl-C because raw mode took it away from the signal it usually raises, and the operator
/// must get the same answer from the same key. Escape as well, there being nothing else for
/// it to mean while a turn has no input box to leave.
fn interrupts(key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Char('c') => key.modifiers.contains(KeyModifiers::CONTROL),
        KeyCode::Esc => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    #[test]
    fn ctrl_c_and_escape_stop_the_turn() {
        assert!(interrupts(key(KeyCode::Char('c'), KeyModifiers::CONTROL)));
        assert!(interrupts(key(KeyCode::Esc, KeyModifiers::NONE)));
    }

    /// A bare `c` is a keystroke, not a verdict: ending a turn on it would make the screen
    /// unusable the moment it takes typed input.
    #[test]
    fn an_unmodified_c_does_not() {
        assert!(!interrupts(key(KeyCode::Char('c'), KeyModifiers::NONE)));
        assert!(!interrupts(key(KeyCode::Char('C'), KeyModifiers::SHIFT)));
        assert!(!interrupts(key(KeyCode::Enter, KeyModifiers::NONE)));
    }

    /// The watch channel keeps one value, so a key pressed after the interrupt must not be
    /// what the turn reads.
    #[test]
    fn an_interrupt_survives_a_later_keypress() {
        let mut seen = Seen::default();

        for pressed in [
            key(KeyCode::Char('c'), KeyModifiers::CONTROL),
            key(KeyCode::Char('x'), KeyModifiers::NONE),
        ] {
            seen.presses += 1;
            seen.stop |= interrupts(pressed);
        }

        assert!(seen.stop);
        assert_eq!(seen.presses, 2);
    }
}
