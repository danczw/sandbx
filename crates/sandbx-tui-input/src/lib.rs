//! The keys that interrupt a turn, and what a hangup means.
//!
//! Reads them off the terminal `sandbx-screen` took, on threads of its own because neither
//! `poll` nor crossterm's `event::read` can be cancelled. Nothing here draws, and nothing
//! here holds a policy, a provider, a session or a gate.

use std::fs::File;
use std::io::{self, IsTerminal};
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::Arc;
use std::time::Duration;
use std::{future, thread};

use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use tokio::sync::watch;

/// Everything in `revents` that means the descriptor will never carry input again. Linux
/// reports these whatever the mask asked for, so a `poll` asking nothing sees these alone.
const GONE: PollFlags = PollFlags::POLLHUP
    .union(PollFlags::POLLERR)
    .union(PollFlags::POLLNVAL);

/// What the reader has seen so far; `stop` and `gone` are sticky, the channel's one slot
/// losing either unread otherwise.
#[derive(Debug, Clone, Copy, Default)]
struct Seen {
    presses: u64,
    stop: bool,
    gone: bool,
}

/// Why the turn stopped waiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stopped {
    /// The operator asked: ctrl-c or escape.
    Pressed,
    /// The terminal hung up. Nothing can be drawn and no key can arrive, so the turn is
    /// ended rather than left running unwatched (#264).
    Gone,
}

/// The keys the operator presses, as the turn awaits them. Start only after
/// `sandbx_screen::Screen::enter`: without raw mode ctrl-c is a signal, not a key.
pub struct Keys {
    seen: watch::Receiver<Seen>,
}

impl Keys {
    /// Start reading keys, and watching for the terminal going away, on two threads that
    /// outlive the turn: neither `poll` nor `event::read` can be cancelled.
    ///
    /// Two threads, each covering what the other cannot — `guide-tui.md` has which (#264).
    pub fn listen() -> Self {
        let (sender, seen) = watch::channel(Seen::default());

        // Owned by the threads, not borrowed from here: an fd closed in this frame could be
        // reopened as something else before `poll` read it. A failure to resolve is one
        // `event::read` would hit too, so no thread starts and the dropped sender closes the
        // channel at once.
        if let Ok(tty) = Tty::resolve() {
            let tty = Arc::new(tty);
            let sender = Arc::new(sender);

            let watched = Arc::clone(&tty);
            let watching = Arc::clone(&sender);
            let out = io::stdout();
            // `as_fd` inside the closure, never across the spawn, which needs `'static`.
            thread::spawn(move || hangup(&watching, watched.as_fd(), out.as_fd()));

            let out = io::stdout();
            thread::spawn(move || read(&sender, tty.as_fd(), out.as_fd(), &mut Crossterm));
        }

        Self { seen }
    }

    /// Resolves on the first thing that means "stop this turn", saying which; never on a
    /// closed channel, which must not end a turn nobody asked to end. A hangup is not that
    /// — it is a descriptor the kernel reported had hung up.
    pub async fn stop(&mut self) -> Stopped {
        loop {
            if let Some(stopped) = stopped(*self.seen.borrow_and_update()) {
                return stopped;
            }

            if self.seen.changed().await.is_err() {
                future::pending::<()>().await;
            }
        }
    }

    /// Resolves on the next key of any kind, for holding a finished screen; at once if the
    /// terminal is gone, since with no key able to arrive, waiting would hold the alternate
    /// screen until the process was killed.
    ///
    /// Off `gone` and not off the channel closing: where only the watch saw the hangup, the
    /// reader is wedged inside crossterm holding its sender, and the channel never closes.
    /// The borrow marks the value seen, so a hangup landing after it still wakes the wait.
    pub async fn press(&mut self) {
        if self.seen.borrow_and_update().gone {
            return;
        }

        let _ = self.seen.changed().await;
    }
}

/// Whatever crossterm reads keys from, owned so the thread holding it keeps the fd open.
enum Tty {
    /// Standard input, when it is a terminal — crossterm's own first choice.
    Stdin(io::Stdin),
    /// `/dev/tty`, crossterm's fallback for a redirected standard input.
    Device(File),
}

impl Tty {
    /// Open the descriptor crossterm will read, the way crossterm resolves it
    /// (`terminal::sys::file_descriptor::tty_fd`, crossterm 0.29): read-write, because that
    /// is the mode crossterm opens it in and a hangup must be read off the same object.
    fn resolve() -> io::Result<Self> {
        let stdin = io::stdin();
        if stdin.is_terminal() {
            return Ok(Self::Stdin(stdin));
        }

        File::options()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map(Self::Device)
    }
}

impl AsFd for Tty {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            Self::Stdin(stdin) => stdin.as_fd(),
            Self::Device(device) => device.as_fd(),
        }
    }
}

/// One question put to crossterm: the next event, or none waiting.
///
/// A trait so the loop in [`read`] is reachable in a test — crossterm's reader is a
/// process-global over standard input or `/dev/tty`, which no test can aim at a pty of its
/// own. Both calls behind one method, so the loop cannot reach past its gate.
trait Source {
    fn next(&mut self) -> io::Result<Option<Event>>;
}

/// crossterm itself.
struct Crossterm;

impl Source for Crossterm {
    fn next(&mut self) -> io::Result<Option<Event>> {
        // The read behind a true poll cannot block: crossterm enqueues the event it polled
        // before answering true, and pops that queue before touching the terminal (0.29).
        if event::poll(Duration::ZERO)? {
            event::read().map(Some)
        } else {
            Ok(None)
        }
    }
}

/// Read keys until the channel closes, the terminal hangs up, or it stops answering.
fn read(
    sender: &watch::Sender<Seen>,
    tty: BorrowedFd<'_>,
    out: BorrowedFd<'_>,
    source: &mut impl Source,
) {
    // While crossterm may still hold a parsed event: one read can carry a ctrl-c behind
    // ordinary bytes, and a poll hands back one event per call.
    let mut buffered = true;

    loop {
        let wait = if buffered {
            PollTimeout::ZERO
        } else {
            PollTimeout::NONE
        };

        // Ahead of every call into crossterm: on a hung-up terminal `event::read` loops on
        // a zero-byte read with no timeout check at all (crossterm 0.29,
        // `event::source::unix::mio`), so a hangup is seen here or never.
        match hung_up(tty, out, PollFlags::POLLIN, wait) {
            // Bytes queued before the terminal died are abandoned, a dead pty reporting
            // `POLLIN|POLLHUP` together: parsing them puts crossterm back in that loop for
            // whatever they did not complete.
            Ok(true) => break,
            // crossterm handles `SIGWINCH` and `poll` is not restarted by `SA_RESTART`, so a
            // resize arrives as `EINTR`. Returning on it would end the reader on every
            // resize of a healthy window, losing the key that stops the turn.
            Err(Errno::EINTR) => continue,
            Err(_) => return,
            Ok(false) => {}
        }

        match source.next() {
            // `Press` only: Windows also reports a release per key, which would double-count.
            Ok(Some(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                buffered = true;
                sender.send_modify(|seen| pressed(seen, key));

                if sender.is_closed() {
                    return;
                }
            }
            // Resize, mouse, paste, focus: ignored; a redraw is driven by the event stream.
            Ok(Some(_)) => buffered = true,
            Ok(None) => buffered = false,
            Err(_) => return,
        }
    }

    sender.send_modify(|seen| seen.gone = true);
}

/// Wait for either descriptor to hang up, and say so once one has.
///
/// Its own thread, calling into no library: this covers the hangup that lands while the
/// reader is inside crossterm, which spins on it rather than returning.
///
/// Nothing asked of either descriptor, so it wakes on a hangup and on nothing else. Asking
/// `POLLIN` as the gate does would wake it on the operator's first ordinary keypress, read
/// that back as "not a hangup", and end the one thread covering that window.
fn hangup(sender: &watch::Sender<Seen>, tty: BorrowedFd<'_>, out: BorrowedFd<'_>) {
    loop {
        match hung_up(tty, out, PollFlags::empty(), PollTimeout::NONE) {
            Ok(true) => break,
            Err(Errno::EINTR) => continue,
            // Asking nothing and waiting unbounded, so this is a `revents` nix cannot name
            // or an error that is not a resize — polling again would answer the same.
            Ok(false) | Err(_) => return,
        }
    }

    sender.send_modify(|seen| seen.gone = true);
}

/// Whether `tty` or `out` has hung up, having waited `wait` for one of them to.
///
/// Both, because under `sandbx tui -- prompt < /dev/pts/5` the screen and the keys are two
/// different ptys, and either one dying leaves the turn undrawable.
///
/// `asked` is what the caller wants of `tty` besides a hangup — the two masks are the
/// mechanism, and `guide-tui.md` has why. Nothing is ever asked of `out`: `POLLIN` would
/// report input on a standard output nobody reads from and spin the caller's loop.
fn hung_up(
    tty: BorrowedFd<'_>,
    out: BorrowedFd<'_>,
    asked: PollFlags,
    wait: PollTimeout,
) -> nix::Result<bool> {
    let mut watched = [
        PollFd::new(tty, asked),
        PollFd::new(out, PollFlags::empty()),
    ];
    poll(&mut watched, wait)?;

    // A `revents` nix cannot name is read as live: Linux never sets one unasked, and a
    // wrong hangup would end a healthy turn, which is the worse direction.
    Ok(watched
        .iter()
        .any(|fd| fd.revents().is_some_and(|revents| revents.intersects(GONE))))
}

/// Fold one keypress into what the reader has seen.
fn pressed(seen: &mut Seen, key: KeyEvent) {
    seen.presses += 1;
    seen.stop |= interrupts(key);
}

/// What `seen` means for a turn still waiting, if anything.
///
/// The keypress first: no key can arrive after a hangup, so a `stop` that is set is an
/// operator who really did ask, whatever became of the terminal afterwards.
fn stopped(seen: Seen) -> Option<Stopped> {
    seen.stop
        .then_some(Stopped::Pressed)
        .or(seen.gone.then_some(Stopped::Gone))
}

/// Whether `key` means "stop this turn": ctrl-c, since raw mode took it from the signal it
/// would otherwise raise; and escape, there being no input box for it to leave instead.
fn interrupts(key: KeyEvent) -> bool {
    key.code == KeyCode::Esc
        || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
}

#[cfg(test)]
#[path = "tui_input_tests.rs"]
mod tests;
