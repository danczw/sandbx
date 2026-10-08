//! The key reader, and what the turn learns from it.

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use tokio::sync::watch;

/// What the reader has seen so far; `stop` is sticky, the channel's one slot losing it
/// unread otherwise.
#[derive(Debug, Clone, Copy, Default)]
struct Seen {
    presses: u64,
    stop: bool,
}

/// The keys the operator presses, as the turn awaits them. Start only after
/// [`Screen::enter`](crate::Screen::enter): without raw mode ctrl-c is a signal, not a key.
pub struct Keys {
    seen: watch::Receiver<Seen>,
}

impl Keys {
    /// Start reading keys on a thread that outlives the turn: `event::read` can't be cancelled,
    /// so it parks, holding no state, until the next key or process exit — holding crossterm's
    /// one reader lock, so [`Screen::redraw`](crate::Screen::redraw) must avoid a question
    /// answered on stdin.
    pub fn listen() -> Self {
        let (sender, seen) = watch::channel(Seen::default());
        std::thread::spawn(move || read(&sender));

        Self { seen }
    }

    /// Resolves on the first key that means "stop this turn"; never on a reader that's gone,
    /// since a closed channel must not end a turn nobody asked to end.
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

    /// Resolves on the next key of any kind, for holding a finished screen; at once if the
    /// reader is gone — opposite [`stop`](Self::stop), since with no key able to arrive,
    /// waiting would hold the alternate screen until the process was killed.
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
            // `Press` only: Windows also reports a release per key, which would double-count.
            Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => {
                seen.presses += 1;
                seen.stop |= interrupts(key);

                if sender.send(seen).is_err() {
                    return;
                }
            }
            // Resize, mouse, paste, focus: ignored; a redraw is driven by the event stream.
            Ok(_) => {}
            // Not retried: the descriptor is gone, and looping would spin the thread at full speed.
            Err(_) => return,
        }
    }
}

/// Whether `key` means "stop this turn": ctrl-c, since raw mode took it from the signal it
/// would otherwise raise; and escape, there being no input box for it to leave instead.
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

    /// A bare `c` must not stop the turn, or the screen is unusable once it takes typed input.
    #[test]
    fn an_unmodified_c_does_not() {
        assert!(!interrupts(key(KeyCode::Char('c'), KeyModifiers::NONE)));
        assert!(!interrupts(key(KeyCode::Char('C'), KeyModifiers::SHIFT)));
        assert!(!interrupts(key(KeyCode::Enter, KeyModifiers::NONE)));
    }

    /// The channel keeps one value, so a later keypress must not overwrite the interrupt.
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
