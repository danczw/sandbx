//! The key reader, the watch for a terminal that went away, and what the turn learns.

use std::fs::File;
use std::io::{self, IsTerminal};
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::Arc;
use std::time::Duration;

use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use tokio::sync::watch;

/// Everything in `revents` that means the descriptor will never carry input again. Linux
/// reports these whatever was asked for, so a `poll` requesting nothing still sees a hangup
/// — and sees nothing else.
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
/// [`Screen::enter`](crate::Screen::enter): without raw mode ctrl-c is a signal, not a key.
pub struct Keys {
    seen: watch::Receiver<Seen>,
}

impl Keys {
    /// Start reading keys, and watching for the terminal going away, on two threads that
    /// outlive the turn: neither `poll` nor `event::read` can be cancelled.
    ///
    /// Two threads because each covers what the other cannot. `read` gates every call into
    /// crossterm on a `poll`, so a hangup almost always lands where it can be seen; the
    /// watch catches the remainder, where the hangup arrives while the reader is inside
    /// crossterm and crossterm spins on it forever (#264).
    pub fn listen() -> Self {
        let (sender, seen) = watch::channel(Seen::default());

        // Resolved once and owned by the threads: a borrowed descriptor cannot outlive this
        // call, and an fd closed here could be reopened as something else before `poll`
        // reads it. A failure is one `event::read` would hit too, crossterm resolving the
        // same descriptor the same way — so no thread starts, and the dropped sender closes
        // the channel at once.
        if let Ok(tty) = Tty::resolve() {
            let tty = Arc::new(tty);
            let sender = Arc::new(sender);

            let watched = Arc::clone(&tty);
            let watching = Arc::clone(&sender);
            let out = io::stdout();
            // `as_fd` inside each closure, never across the spawn: the borrow has to come
            // from the owner the thread itself holds.
            std::thread::spawn(move || hangup(&watching, watched.as_fd(), out.as_fd()));

            let out = io::stdout();
            std::thread::spawn(move || read(&sender, tty.as_fd(), out.as_fd(), &mut Crossterm));
        }

        Self { seen }
    }

    /// Resolves on the first thing that means "stop this turn", saying which; never on a
    /// reader that is merely gone, since a closed channel must not end a turn nobody asked
    /// to end. A hangup is not that: it is a descriptor the kernel reported had hung up.
    pub async fn stop(&mut self) -> Stopped {
        loop {
            if let Some(stopped) = stopped(*self.seen.borrow_and_update()) {
                return stopped;
            }

            if self.seen.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }

    /// Resolves on the next key of any kind, for holding a finished screen; at once if the
    /// terminal is gone — opposite [`stop`](Self::stop), since with no key able to arrive,
    /// waiting would hold the alternate screen until the process was killed.
    ///
    /// Read off `gone` rather than off the channel closing: in the window the hangup watch
    /// exists for, the reader is wedged inside crossterm forever and holds its sender, so
    /// the channel never closes. The borrow also marks the value seen, so a hangup landing
    /// after it still wakes the wait below.
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
/// A trait so the loop in [`read`] is reachable in a test: crossterm's reader is a
/// process-global over standard input or `/dev/tty`, which no test can aim at a pty of its
/// own. Both calls behind one method, so the loop cannot reach past its gate into a
/// `event::read` that never returns.
trait Source {
    fn next(&mut self) -> io::Result<Option<Event>>;
}

/// crossterm itself.
struct Crossterm;

impl Source for Crossterm {
    fn next(&mut self) -> io::Result<Option<Event>> {
        // The read behind a true poll cannot block: crossterm enqueues the event it polled
        // before answering true, and pops that queue before touching the terminal again
        // (`event::read` internals, crossterm 0.29).
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
        // a `read` returning zero bytes with no timeout check at all (crossterm 0.29,
        // `event::source::unix::mio`), so a hangup is seen here or never.
        match hung_up(tty, out, PollFlags::POLLIN, wait) {
            // Bytes the terminal queued before it died are abandoned: a dead pty reports
            // `POLLIN|POLLHUP` in one `revents`, and parsing them would put crossterm back
            // in the loop above for whatever those bytes did not complete.
            Ok(true) => break,
            // crossterm handles `SIGWINCH`, and `poll` is not restarted by `SA_RESTART`: a
            // resize arrives here as `EINTR`. Returning on it would end the reader on every
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
/// Its own thread, calling into no library: [`read`]'s gate covers a hangup that lands while
/// the reader is between calls, and this covers one that lands while the reader is inside
/// crossterm — where crossterm spins on it rather than returning.
///
/// Nothing asked of either descriptor, so this wakes on a hangup and on nothing else. Asking
/// `POLLIN` of the keyboard the way the gate does would wake this on the operator's first
/// ordinary keypress, read it back as "not a hangup", and end the one thread covering that
/// window — leaving #264 one keystroke away.
fn hangup(sender: &watch::Sender<Seen>, tty: BorrowedFd<'_>, out: BorrowedFd<'_>) {
    loop {
        match hung_up(tty, out, PollFlags::empty(), PollTimeout::NONE) {
            Ok(true) => break,
            Err(Errno::EINTR) => continue,
            // Asking for nothing and waiting without bound, so this is a `revents` nix
            // cannot name or an error that is not a resize — neither a hangup nor worth
            // polling again for. The gate in `read` is what is left.
            Ok(false) | Err(_) => return,
        }
    }

    sender.send_modify(|seen| seen.gone = true);
}

/// Whether `tty` or `out` has hung up, having waited `wait` for one of them to.
///
/// Both, because `tui` validates standard output while crossterm reads standard input: under
/// `sandbx tui -- prompt < /dev/pts/5` the screen and the keys are two different ptys, and
/// either one dying leaves the turn undrawable.
///
/// `asked` is what the caller wants of `tty` besides a hangup: `POLLIN` for [`read`], which
/// learns from the same call when crossterm has bytes to parse, and nothing for [`hangup`],
/// which a keypress may not wake. Nothing is ever asked of `out` — an empty mask still
/// reports a hangup, where `POLLIN` would also report input on a standard output nobody
/// reads from and spin the caller's loop.
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
    if seen.stop {
        return Some(Stopped::Pressed);
    }

    seen.gone.then_some(Stopped::Gone)
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
    use std::io::Write;

    use super::*;

    fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    /// A pty pair, and no controlling terminal: closing the master is then a hangup on the
    /// slave rather than a `SIGHUP` that kills the test binary.
    ///
    /// Echo off, so what the slave reads is only what the master wrote.
    fn pty() -> (File, File) {
        use nix::sys::termios;

        let pair = nix::pty::openpty(None, None).expect("a pty pair");

        let mut attrs = termios::tcgetattr(&pair.slave).expect("the pty's termios");
        attrs.local_flags.remove(termios::LocalFlags::ECHO);
        termios::tcsetattr(&pair.slave, termios::SetArg::TCSANOW, &attrs).expect("echo off");

        (File::from(pair.master), File::from(pair.slave))
    }

    /// Whether `future` finishes without ever being woken. No runtime, because what is under
    /// test is that `press` answers from the value the channel already holds rather than from
    /// a notification — which is exactly one poll with a waker nothing can call.
    fn ready(future: impl Future<Output = ()>) -> bool {
        let mut future = std::pin::pin!(future);
        let mut polling = std::task::Context::from_waker(std::task::Waker::noop());

        future.as_mut().poll(&mut polling).is_ready()
    }

    /// Wait for `fd` to carry something, or fail the test.
    ///
    /// Not a sleep: a pty queues a written line from a workqueue, and a poll that ran before
    /// it was queued would leave the test asserting nothing.
    fn wait_readable(fd: &impl AsFd) {
        let mut watched = [PollFd::new(fd.as_fd(), PollFlags::POLLIN)];
        let ready = poll(&mut watched, PollTimeout::from(5_000u16)).expect("poll");

        assert_eq!(ready, 1, "the pty queued nothing within five seconds");
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

        for key in [
            key(KeyCode::Char('c'), KeyModifiers::CONTROL),
            key(KeyCode::Char('x'), KeyModifiers::NONE),
        ] {
            pressed(&mut seen, key);
        }

        assert!(seen.stop);
        assert_eq!(seen.presses, 2);
    }

    /// A hangup ends the turn, where a closed channel does not — and a key the operator
    /// really pressed is still accounted to them rather than to the terminal.
    #[test]
    fn a_hangup_stops_the_turn_and_a_keypress_outranks_it() {
        let seen = |stop, gone| Seen {
            presses: 0,
            stop,
            gone,
        };

        // The first case is what keeps the rest honest: a reader that has seen nothing
        // leaves the turn running.
        assert_eq!(stopped(seen(false, false)), None);
        assert_eq!(stopped(seen(false, true)), Some(Stopped::Gone));
        assert_eq!(stopped(seen(true, false)), Some(Stopped::Pressed));
        assert_eq!(stopped(seen(true, true)), Some(Stopped::Pressed));
    }

    /// The whole of #264: a hangup is read off a `poll`, there being no `read` crossterm
    /// returns from once the terminal is gone.
    #[test]
    fn a_hung_up_terminal_is_seen_and_a_live_one_is_not() {
        let asked = PollFlags::POLLIN;

        let (master, dead) = pty();
        drop(master);
        assert!(hung_up(dead.as_fd(), dead.as_fd(), asked, PollTimeout::ZERO).expect("poll"));

        // Non-vacuous: a live pty answers no, so the answer above is the hangup and not the
        // call. Bounded rather than blocking, a quiet pty never satisfying `POLLIN`.
        let (_master, live) = pty();
        let wait = PollTimeout::from(50u16);
        assert!(!hung_up(live.as_fd(), live.as_fd(), asked, wait).expect("poll"));
    }

    /// Input is not a hangup: both arrive in one `revents` on a dead pty (`POLLIN|POLLHUP`),
    /// so only the flags tell a terminal with something to say from one with nothing left.
    #[test]
    fn pending_input_is_not_a_hangup() {
        let (mut master, slave) = pty();
        writeln!(master, "x").expect("the typed line");
        // Queued before the poll runs, or this asserts nothing about pending input.
        wait_readable(&slave);

        let asked = PollFlags::POLLIN;
        assert!(!hung_up(slave.as_fd(), slave.as_fd(), asked, PollTimeout::ZERO).expect("poll"));
    }

    /// And the watch is not woken by it at all. With `POLLIN` the operator's first ordinary
    /// keypress would wake that thread, read back as "not a hangup" and end it — leaving the
    /// window where the reader is already inside crossterm uncovered from then on.
    ///
    /// The timeout is the whole assertion: a mask that took the input would have answered at
    /// once. A slow machine only waits longer, so the measurement cannot fail falsely.
    #[test]
    fn pending_input_does_not_wake_the_watch() {
        let (mut master, slave) = pty();
        writeln!(master, "x").expect("the typed line");
        wait_readable(&slave);

        let wait = Duration::from_millis(50);
        let polled = std::time::Instant::now();
        let gone = hung_up(
            slave.as_fd(),
            slave.as_fd(),
            PollFlags::empty(),
            PollTimeout::try_from(wait).expect("a timeout in range"),
        )
        .expect("poll");
        let waited = polled.elapsed();

        assert!(!gone, "a live pty was reported as hung up");
        assert!(waited >= wait, "the watch woke on input after {waited:?}");
    }

    /// Either descriptor, because `tui` validates standard output while crossterm reads
    /// standard input: under a redirected stdin those are two different ptys, and a screen
    /// that died is as unwatched as a keyboard that did.
    #[test]
    fn a_hangup_on_the_screens_descriptor_alone_is_seen() {
        let (_master, live) = pty();
        let (master, dead) = pty();
        drop(master);

        let (sender, seen) = watch::channel(Seen::default());
        assert!(!seen.borrow().gone, "the fixture starts out gone");

        hangup(&sender, live.as_fd(), dead.as_fd());

        assert!(seen.borrow().gone);
    }

    /// The gate ahead of crossterm is what removes the spin: `event::read` on a hung-up
    /// terminal loops on a zero-byte read forever, so a loop that reached it never returns.
    #[test]
    fn a_reader_on_a_hung_up_terminal_enters_no_source() {
        struct Unreachable;

        impl Source for Unreachable {
            fn next(&mut self) -> io::Result<Option<Event>> {
                panic!("a hung-up terminal was let through to crossterm");
            }
        }

        let (master, dead) = pty();
        drop(master);
        let (sender, seen) = watch::channel(Seen::default());

        read(&sender, dead.as_fd(), dead.as_fd(), &mut Unreachable);

        assert!(seen.borrow().gone, "the reader returned without saying why");
    }

    /// The pair the one above needs: on a live terminal the same loop does read its source,
    /// so the gate is a hangup check and not a reader that reads nothing.
    #[test]
    fn a_reader_on_a_live_terminal_reads_its_source() {
        /// One ctrl-c, then a failure — which ends the loop without a second terminal event
        /// and without reporting a hangup.
        #[derive(Default)]
        struct Typed {
            asked: u32,
        }

        impl Source for Typed {
            fn next(&mut self) -> io::Result<Option<Event>> {
                self.asked += 1;
                if self.asked == 1 {
                    let pressed = key(KeyCode::Char('c'), KeyModifiers::CONTROL);
                    return Ok(Some(Event::Key(pressed)));
                }

                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }
        }

        let (_master, live) = pty();
        let (sender, seen) = watch::channel(Seen::default());
        let mut source = Typed::default();

        read(&sender, live.as_fd(), live.as_fd(), &mut source);

        assert_eq!(source.asked, 2, "the gate held up a live terminal");
        let seen = seen.borrow();
        assert_eq!((seen.presses, seen.stop), (1, true));
        assert!(!seen.gone, "a live terminal was reported as hung up");
    }

    /// The finished screen is not held on a terminal that already went away — and the
    /// sender stays alive for the poll, so what resolves `press` is the hangup and not a
    /// channel that closed. It has to be: where the watch is the only thread that saw the
    /// hangup, the reader is still wedged inside crossterm holding the other sender.
    #[test]
    fn a_hangup_releases_a_screen_waiting_on_the_final_key() {
        let (sender, seen) = watch::channel(Seen {
            presses: 0,
            stop: false,
            gone: true,
        });
        let mut keys = Keys { seen };

        assert!(
            ready(keys.press()),
            "a finished screen outlived its terminal"
        );

        drop(sender);
    }

    /// The pair: with no hangup recorded the wait stands, so the test above is the flag and
    /// not a `press` that waits for nothing.
    #[test]
    fn a_live_terminal_still_holds_it() {
        let (sender, seen) = watch::channel(Seen::default());
        let mut keys = Keys { seen };

        assert!(!ready(keys.press()), "the screen was dropped unread");

        drop(sender);
    }
}
