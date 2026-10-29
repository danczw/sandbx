use std::io::Write;

use sandbx_pty_fixture::pty;

use super::{Keys, Seen, Source, Stopped, hangup, hung_up, interrupts, pressed, read, stopped};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use ratatui::crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use std::io;
use std::os::fd::AsFd;
use std::time::Duration;
use tokio::sync::watch;

fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
    KeyEvent::new(code, modifiers)
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

/// And the watch is not woken by it at all: with `POLLIN` the operator's first keypress
/// would end the one thread covering a hangup that lands inside crossterm.
///
/// The timeout is the whole assertion — a mask that took the input would have answered
/// at once, and a slow machine only waits longer.
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

/// The finished screen is not held on a terminal that already went away. The sender
/// stays alive, so what resolves `press` is the hangup and not a closed channel — which
/// is the real shape: the wedged reader holds its sender forever.
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
