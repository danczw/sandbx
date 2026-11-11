//! The keys that interrupt a turn, the keys that answer a question put to the operator,
//! and what a hangup means.
//!
//! Reads them off the terminal `sandbx-screen` took, on threads of its own because neither
//! `poll` nor crossterm's `event::read` can be cancelled. Nothing here draws, and nothing
//! here holds a policy, a provider, a session or a gate: which keys answer, and what an
//! answer means, are the caller's.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, IsTerminal};
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use std::{future, thread};

use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::termios::{FlushArg, tcflush};
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
    ///
    /// Reached only by a hangup that raised no `SIGHUP`: sandbx handles none, so an emulator
    /// closing the master kills the foreground group at 129 first. `nohup`, `setsid`, an
    /// orphaned group, `trap '' HUP`, a dying descriptor that is not the controlling
    /// terminal, or an `openpty` pair that never became one — which is what the tests use.
    Gone,
}

/// What the reader thread, the hangup thread and [`Answers`] share.
struct Wire {
    /// What the turn awaits. A watch because [`Keys::stop`] is async, and the state is
    /// read back from here by [`Answers::wait`] so the two cannot disagree.
    seen: watch::Sender<Seen>,
    slate: Mutex<Slate>,
    /// Signalled on every change a [`Answers::wait`] could be parked on.
    wake: Condvar,
}

/// The state of one question, behind the lock a parked [`Answers::wait`] sleeps on.
///
/// Never held across a call into crossterm, which can spin on a hung-up terminal: the
/// hangup thread has to take it to wake a wait, and is the one thing that ends the spin.
#[derive(Default)]
struct Slate {
    /// Answer keys are being kept.
    armed: bool,
    /// Asked for while the reader was inside a burst of events it had already taken off the
    /// terminal. Those predate the question, so it opens when the reader next goes quiet.
    pending: bool,
    /// The reader is blocked on the terminal with nothing buffered anywhere: every byte it
    /// reads from here on arrived after this was set.
    idle: bool,
    accepts: &'static [char],
    keys: VecDeque<char>,
    /// The reader has exited, for whatever reason: nobody is left to answer.
    done: bool,
}

impl Wire {
    fn new() -> Self {
        Self {
            seen: watch::channel(Seen::default()).0,
            slate: Mutex::new(Slate::default()),
            wake: Condvar::new(),
        }
    }

    /// A poisoned lock still holds a queue of chars, which nothing here can leave half
    /// written, so it is taken rather than panicked on.
    fn slate(&self) -> MutexGuard<'_, Slate> {
        self.slate.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Wake a parked wait after a change made outside the lock: taking it first is what
    /// stops the change landing between the wait's check and its sleep.
    fn wake(&self) {
        drop(self.slate());
        self.wake.notify_all();
    }

    fn gone(&self) {
        self.seen.send_modify(|seen| seen.gone = true);
        self.wake();
    }

    /// Record one key press: an interrupt latches, an answer is kept if one is asked for.
    fn pressed(&self, key: KeyEvent) {
        self.seen.send_modify(|seen| pressed(seen, key));

        let mut slate = self.slate();
        if slate.armed
            && let Some(answer) = answer(key, slate.accepts)
        {
            slate.keys.push_back(answer);
        }
        drop(slate);
        self.wake.notify_all();
    }

    /// The reader is about to block on the terminal, or has stopped doing so.
    fn set_idle(&self, idle: bool) {
        let mut slate = self.slate();
        slate.idle = idle;
        if idle && slate.pending {
            slate.pending = false;
            slate.armed = true;
        }
    }
}

/// What [`Answers::wait`] came back with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// The operator pressed one of the keys asked for.
    Key(char),
    /// ctrl-c or escape, already latched for [`Keys::stop`].
    Interrupted,
    /// Nobody can answer: the terminal hung up, or the reader stopped.
    Closed,
}

/// The operator's answer to one question, read off the keys [`Keys`] reads.
///
/// For a caller that cannot await: a gate is a plain function on the async task, so what it
/// can wait on is a thread the runtime does not drive, which is what this is.
#[derive(Clone)]
pub struct Answers {
    wire: Arc<Wire>,
    /// `None` where the terminal could not be resolved and no reader is running.
    tty: Option<Arc<Tty>>,
}

impl Answers {
    fn new(wire: Arc<Wire>, tty: Option<Arc<Tty>>) -> Self {
        Self { wire, tty }
    }

    /// Open a question: forget every key pressed so far, and keep from here on only those
    /// in `accepts`, exactly as typed. Call after the question is drawn, never before: a key
    /// pressed while nothing was on screen to answer must not count as an answer to it.
    ///
    /// The kernel's queue is cleared and the reader's burst is not kept, the keys sitting
    /// behind one another having all been typed before this. Either alone leaves the way
    /// open, as for `tcflush` and the line buffer in front of a line prompt.
    ///
    /// # Errors
    ///
    /// When the terminal could not be cleared, or there is none. Nothing is armed: a
    /// question is not to be asked over a queue that may already hold its answer.
    pub fn arm(&self, accepts: &'static [char]) -> nix::Result<()> {
        let tty = self.tty.as_ref().ok_or(Errno::ENOTTY)?;

        let mut slate = self.wire.slate();
        slate.armed = false;
        slate.pending = false;
        slate.keys.clear();
        slate.accepts = accepts;

        if slate.idle {
            // The reader is blocked and holds nothing: only the kernel can hold a key that
            // predates this. Under the lock, so none is read between the flush and the arm.
            tcflush(tty.as_fd(), FlushArg::TCIFLUSH)?;
            slate.armed = true;
        } else {
            slate.pending = true;
        }

        Ok(())
    }

    /// Block until the operator answers, interrupts, or can no longer be asked.
    ///
    /// No timeout, as a prompt on a terminal has none. An interrupt outranks an answer
    /// already pressed, and a hangup outranks both: both leave the call refused, which is
    /// the direction a doubtful reading must lean.
    #[must_use]
    pub fn wait(&self) -> Reply {
        let mut slate = self.wire.slate();
        let reply = loop {
            let seen = *self.wire.seen.borrow();
            if seen.stop {
                break Reply::Interrupted;
            }
            if seen.gone || slate.done {
                break Reply::Closed;
            }
            if let Some(answer) = slate.keys.pop_front() {
                break Reply::Key(answer);
            }

            slate = self
                .wire
                .wake
                .wait(slate)
                .unwrap_or_else(PoisonError::into_inner);
        };

        slate.armed = false;
        slate.pending = false;
        slate.keys.clear();

        reply
    }
}

/// The keys the operator presses, as the turn awaits them. Start only after
/// `sandbx_screen::Screen::enter`: without raw mode ctrl-c is a signal, not a key.
pub struct Keys {
    seen: watch::Receiver<Seen>,
    answers: Answers,
}

impl Keys {
    /// Start reading keys, and watching for the terminal going away, on two threads that
    /// outlive the turn: neither `poll` nor `event::read` can be cancelled.
    ///
    /// Two threads, each covering what the other cannot (#264): `read` gates every call into
    /// crossterm on a `poll`, so a hangup is seen before anything that would spin on it, and
    /// `hangup` covers the one landing while the reader is already inside crossterm.
    pub fn listen() -> Self {
        let wire = Arc::new(Wire::new());
        let seen = wire.seen.subscribe();

        // Owned by the threads, not borrowed from here: an fd closed in this frame could be
        // reopened as something else before `poll` read it. A failure to resolve is one
        // `event::read` would hit too, so no thread starts, and `Answers::arm` refuses.
        let tty = Tty::resolve().ok().map(Arc::new);
        if let Some(tty) = &tty {
            let watched = Arc::clone(tty);
            let watching = Arc::clone(&wire);
            let out = io::stdout();
            // `as_fd` inside the closure, never across the spawn, which needs `'static`.
            thread::spawn(move || hangup(&watching, watched.as_fd(), out.as_fd()));

            let tty = Arc::clone(tty);
            let reading = Arc::clone(&wire);
            let out = io::stdout();
            thread::spawn(move || read(&reading, tty.as_fd(), out.as_fd(), &mut Crossterm));
        }

        Self {
            seen,
            answers: Answers::new(wire, tty),
        }
    }

    /// A handle to ask the operator a question through, which outlives a borrow of `self`
    /// where [`Keys::stop`] holds one.
    #[must_use]
    pub fn answers(&self) -> Answers {
        self.answers.clone()
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
fn read(wire: &Wire, tty: BorrowedFd<'_>, out: BorrowedFd<'_>, source: &mut impl Source) {
    // However this returns, including a panic in `source`: a wait parked on a reader that
    // is gone would never end.
    let _exited = Exited(wire);

    // While crossterm may still hold a parsed event: one read can carry a ctrl-c behind
    // ordinary bytes, and a poll hands back one event per call.
    let mut buffered = true;

    loop {
        let wait = if buffered {
            PollTimeout::ZERO
        } else {
            PollTimeout::NONE
        };

        // Quiet only across a blocking poll, and only once nothing is buffered: a question
        // opens at this point, never mid-burst, which is what keeps a key read before it
        // from answering it.
        wire.set_idle(!buffered);
        let hung = hung_up(tty, out, PollFlags::POLLIN, wait);
        wire.set_idle(false);

        // Ahead of every call into crossterm: on a hung-up terminal `event::read` loops on
        // a zero-byte read with no timeout check at all (crossterm 0.29,
        // `event::source::unix::mio`), so a hangup is seen here or never.
        match hung {
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
                wire.pressed(key);

                if wire.seen.is_closed() {
                    return;
                }
            }
            // Resize, mouse, paste, focus: ignored; a redraw is driven by the event stream.
            Ok(Some(_)) => buffered = true,
            Ok(None) => buffered = false,
            Err(_) => return,
        }
    }

    wire.gone();
}

/// Marks the reader as gone to every wait, on any way out of [`read`].
struct Exited<'a>(&'a Wire);

impl Drop for Exited<'_> {
    fn drop(&mut self) {
        self.0.slate().done = true;
        self.0.wake.notify_all();
    }
}

/// Wait for either descriptor to hang up, and say so once one has.
///
/// Its own thread, calling into no library: this covers the hangup that lands while the
/// reader is inside crossterm, which spins on it rather than returning.
///
/// Nothing asked of either descriptor, so it wakes on a hangup and on nothing else. Asking
/// `POLLIN` as the gate does would wake it on the operator's first ordinary keypress, read
/// that back as "not a hangup", and end the one thread covering that window.
fn hangup(wire: &Wire, tty: BorrowedFd<'_>, out: BorrowedFd<'_>) {
    loop {
        match hung_up(tty, out, PollFlags::empty(), PollTimeout::NONE) {
            Ok(true) => break,
            Err(Errno::EINTR) => continue,
            // Asking nothing and waiting unbounded, so this is a `revents` nix cannot name
            // or an error that is not a resize — polling again would answer the same.
            Ok(false) | Err(_) => return,
        }
    }

    wire.gone();
}

/// Whether `tty` or `out` has hung up, having waited `wait` for one of them to.
///
/// Both, because under `sandbx tui -- prompt < /dev/pts/5` the screen and the keys are two
/// different ptys, and either one dying leaves the turn undrawable.
///
/// `asked` is what the caller wants of `tty` besides a hangup — the two masks are the
/// mechanism, and [`hangup`] has why. Nothing is ever asked of `out`: `POLLIN` would
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

fn pressed(seen: &mut Seen, key: KeyEvent) {
    seen.stop |= interrupts(key);
}

/// The answer `key` is, if it is one of `accepts` pressed on its own: a modified key is a
/// shortcut, not the character, and `Y` is not `y`.
fn answer(key: KeyEvent, accepts: &[char]) -> Option<char> {
    match key.code {
        KeyCode::Char(c) if key.modifiers == KeyModifiers::NONE && accepts.contains(&c) => Some(c),
        _ => None,
    }
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
