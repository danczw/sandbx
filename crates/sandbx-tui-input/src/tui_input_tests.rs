use std::io::Write;
use std::os::fd::AsFd;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};
use std::{io, thread};

use nix::poll::{PollFlags, PollTimeout};
use ratatui::crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use sandbx_pty_fixture::{Pty, pty, wait_readable};

use super::{
    Answers, Reply, Seen, Source, Stopped, Tty, Wire, hangup, hung_up, interrupts, pressed, read,
    stopped,
};

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

    for key in [
        key(KeyCode::Char('c'), KeyModifiers::CONTROL),
        key(KeyCode::Char('x'), KeyModifiers::NONE),
    ] {
        pressed(&mut seen, key);
    }

    assert!(seen.stop);
}

/// A hangup ends the turn, where a closed channel does not — and a key the operator
/// really pressed is still accounted to them rather than to the terminal.
#[test]
fn a_hangup_stops_the_turn_and_a_keypress_outranks_it() {
    let seen = |stop, gone| Seen { stop, gone };

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

    let Pty {
        master,
        slave: dead,
    } = pty();
    drop(master);
    assert!(hung_up(dead.as_fd(), dead.as_fd(), asked, PollTimeout::ZERO).expect("poll"));

    // Non-vacuous: a live pty answers no, so the answer above is the hangup and not the
    // call. Bounded rather than blocking, a quiet pty never satisfying `POLLIN`.
    let Pty {
        master: _master,
        slave: live,
    } = pty();
    let wait = PollTimeout::from(50u16);
    assert!(!hung_up(live.as_fd(), live.as_fd(), asked, wait).expect("poll"));
}

/// Input is not a hangup: both arrive in one `revents` on a dead pty (`POLLIN|POLLHUP`),
/// so only the flags tell a terminal with something to say from one with nothing left.
#[test]
fn pending_input_is_not_a_hangup() {
    let Pty { mut master, slave } = pty();
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
    let Pty { mut master, slave } = pty();
    writeln!(master, "x").expect("the typed line");
    wait_readable(&slave);

    let wait = Duration::from_millis(50);
    let polled = Instant::now();
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
    let Pty {
        master: _master,
        slave: live,
    } = pty();
    let Pty {
        master,
        slave: dead,
    } = pty();
    drop(master);

    let wire = Wire::new();
    assert!(!wire.seen.borrow().gone, "the fixture starts out gone");

    hangup(&wire, live.as_fd(), dead.as_fd());

    assert!(wire.seen.borrow().gone);
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

    let Pty {
        master,
        slave: dead,
    } = pty();
    drop(master);
    let wire = Wire::new();

    read(&wire, dead.as_fd(), dead.as_fd(), &mut Unreachable);

    assert!(
        wire.seen.borrow().gone,
        "the reader returned without saying why"
    );
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

    let Pty {
        master: _master,
        slave: live,
    } = pty();
    let wire = Wire::new();
    // Held as `Keys` holds one: with none, the reader reads a closed channel as a turn
    // that is over and returns after the first key.
    let _keys = wire.seen.subscribe();
    let mut source = Typed::default();

    read(&wire, live.as_fd(), live.as_fd(), &mut source);

    assert_eq!(source.asked, 2, "the gate held up a live terminal");
    let seen = wire.seen.borrow();
    assert!(seen.stop, "the interrupt was not read");
    assert!(!seen.gone, "a live terminal was reported as hung up");
}

/// An `Answers` over a wire nothing reads into, so each test plays the reader's part.
fn answers(tty: std::fs::File) -> Answers {
    Answers::new(Arc::new(Wire::new()), Some(Arc::new(Tty::Device(tty))))
}

/// The reader going quiet, as it does between bursts, on the terminal `answers` holds.
fn quiet(answers: &Answers) {
    let tty = answers.tty.as_ref().expect("a terminal");
    answers.wire.quiet(tty.as_fd()).expect("went quiet");
}

fn typed(c: char) -> KeyEvent {
    key(KeyCode::Char(c), KeyModifiers::NONE)
}

/// Waits on its own thread, bounded: a wait that never wakes would otherwise hang the
/// suite instead of failing it.
fn waited(answers: &Answers) -> Reply {
    let (sent, received) = mpsc::channel();
    let waiting = answers.clone();
    thread::spawn(move || sent.send(waiting.wait()).expect("the test is listening"));

    received
        .recv_timeout(Duration::from_secs(5))
        .expect("the wait never returned")
}

/// The whole of the modal's guard: a `y` typed at a counterfeit question, or just before
/// the real one, is not an answer to it.
#[test]
fn a_key_read_while_the_reader_was_busy_is_not_an_answer() {
    let Pty { master: _m, slave } = pty();
    let answers = answers(slave);

    // Busy, so the arm lands inside a read already under way.
    answers.arm(&['y', 'n']).expect("armed");
    answers.wire.pressed(typed('y'));

    assert!(
        answers.wire.slate().keys.is_empty(),
        "a key read before the reader went quiet was kept as the answer"
    );
}

/// The pair the one above needs: once the reader has gone quiet the same key is the
/// answer, so the guard is the reader's state and not a queue that keeps nothing.
#[test]
fn a_key_read_once_the_reader_is_quiet_is_the_answer() {
    let Pty { master: _m, slave } = pty();
    let answers = answers(slave);
    answers.arm(&['y', 'n']).expect("armed");
    quiet(&answers);

    answers.wire.pressed(typed('y'));

    assert_eq!(waited(&answers), Reply::Key('y'));
}

#[test]
fn only_the_keys_asked_for_are_kept() {
    let Pty { master: _m, slave } = pty();
    let answers = answers(slave);
    quiet(&answers);
    answers.arm(&['y', 'n']).expect("armed");

    for ignored in [
        typed('x'),
        typed('Y'),
        key(KeyCode::Char('y'), KeyModifiers::CONTROL),
        key(KeyCode::Char('y'), KeyModifiers::ALT),
        key(KeyCode::Enter, KeyModifiers::NONE),
    ] {
        answers.wire.pressed(ignored);
    }
    assert!(
        answers.wire.slate().keys.is_empty(),
        "a key nobody asked for was kept"
    );

    answers.wire.pressed(typed('n'));
    assert_eq!(waited(&answers), Reply::Key('n'));
}

/// Armed while the reader is inside a burst of buffered events, the question opens to
/// answers only once the reader has drained them and gone quiet.
#[test]
fn arming_mid_burst_waits_for_the_reader_to_go_quiet() {
    let Pty { master: _m, slave } = pty();
    let answers = answers(slave);

    answers.arm(&['y']).expect("armed");
    assert!(
        !answers.wire.slate().armed,
        "keys of the burst in flight were let in"
    );

    quiet(&answers);
    assert!(
        answers.wire.slate().armed,
        "the question never opened once the reader went quiet"
    );
}

/// Over a real terminal because what an idle arm clears is the kernel's input queue.
#[test]
fn arming_clears_what_was_typed_before() {
    let Pty { mut master, slave } = pty();
    writeln!(master, "y").expect("the typed line");
    wait_readable(&slave);

    let queued = |slave: &std::fs::File| {
        let mut watched = [nix::poll::PollFd::new(slave.as_fd(), PollFlags::POLLIN)];
        nix::poll::poll(&mut watched, PollTimeout::ZERO).expect("poll")
    };
    assert_eq!(
        queued(&slave),
        1,
        "nothing was queued, so nothing is cleared"
    );

    let answers = answers(slave.try_clone().expect("a second handle"));
    quiet(&answers);
    answers.arm(&['y']).expect("armed");

    assert_eq!(queued(&slave), 0, "the typeahead survived the arm");
}

/// Not a terminal, not cleared: the question is not asked over a queue that could not be
/// emptied.
#[test]
fn an_arm_that_could_not_clear_the_queue_is_refused() {
    let file = std::fs::File::open("/dev/null").expect("a descriptor that is no terminal");
    let answers = answers(file);
    quiet(&answers);

    assert!(
        answers.arm(&['y']).is_err(),
        "armed over an uncleared queue"
    );
    assert!(!answers.wire.slate().armed, "left armed after refusing");
}

#[test]
fn an_interrupt_outranks_a_queued_answer() {
    let Pty { master: _m, slave } = pty();
    let answers = answers(slave);
    quiet(&answers);
    answers.arm(&['y']).expect("armed");

    answers.wire.pressed(typed('y'));
    answers
        .wire
        .pressed(key(KeyCode::Char('c'), KeyModifiers::CONTROL));

    assert_eq!(waited(&answers), Reply::Interrupted);
}

/// A stop already latched answers at once, so the calls behind it in a stopped round are
/// not each waited on.
#[test]
fn a_latched_stop_is_not_waited_for() {
    let Pty { master: _m, slave } = pty();
    let answers = answers(slave);
    answers.wire.seen.send_modify(|seen| seen.stop = true);

    assert_eq!(waited(&answers), Reply::Interrupted);
}

#[test]
fn a_hangup_wakes_a_wait_in_progress() {
    let Pty { master: _m, slave } = pty();
    let answers = answers(slave);
    quiet(&answers);
    answers.arm(&['y']).expect("armed");

    let (sent, received) = mpsc::channel();
    let waiting = answers.clone();
    thread::spawn(move || sent.send(waiting.wait()).expect("the test is listening"));
    // Parked first, or this tests only a wait that starts after the hangup.
    assert!(
        received.recv_timeout(Duration::from_millis(100)).is_err(),
        "the wait returned with nothing to return on"
    );

    answers.wire.gone();

    assert_eq!(
        received
            .recv_timeout(Duration::from_secs(5))
            .expect("the hangup never woke the wait"),
        Reply::Closed
    );
}

/// A reader that stopped for any reason other than a hangup leaves nobody to answer, and
/// a wait with no timeout would be the operator staring at a frozen screen.
#[test]
fn a_reader_that_has_exited_ends_the_wait() {
    struct Fails;

    impl Source for Fails {
        fn next(&mut self) -> io::Result<Option<Event>> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    let Pty { master: _m, slave } = pty();
    let answers = answers(slave.try_clone().expect("a second handle"));

    read(&answers.wire, slave.as_fd(), slave.as_fd(), &mut Fails);

    assert!(
        !answers.wire.seen.borrow().gone,
        "the fixture hung up, so this is not the case under test"
    );
    assert_eq!(waited(&answers), Reply::Closed);
}

/// Through the reader itself, because its going quiet is what opens the question: a
/// question armed while it is busy is answered by the first key after it stops being.
#[test]
fn the_reader_opens_the_question_when_it_goes_quiet() {
    /// Nothing waiting, then one `y`, then a failure to end the loop.
    struct Quiet(Vec<io::Result<Option<Event>>>);

    impl Source for Quiet {
        fn next(&mut self) -> io::Result<Option<Event>> {
            self.0.remove(0)
        }
    }

    let Pty { mut master, slave } = pty();

    let answers = answers(slave.try_clone().expect("a second handle"));
    let _keys = answers.wire.seen.subscribe();
    answers.arm(&['y']).expect("armed");
    let mut source = Quiet(vec![
        Ok(Some(Event::Key(typed('y')))),
        Ok(None),
        Ok(Some(Event::Key(typed('y')))),
        Err(io::Error::from(io::ErrorKind::BrokenPipe)),
    ]);

    thread::scope(|scope| {
        // Once the question has opened, which flushes the terminal: a byte written before
        // would be flushed with it and the reader's blocking poll would never return.
        // Borrowing `master`, not moving it: dropped here it would hang the terminal up, and
        // the reader abandons what is queued behind a hangup.
        scope.spawn(|| {
            let waited = Instant::now();
            while !answers.wire.slate().armed && waited.elapsed() < Duration::from_secs(5) {
                thread::yield_now();
            }
            writeln!(master, "x").expect("the typed line");
        });

        read(&answers.wire, slave.as_fd(), slave.as_fd(), &mut source);
    });

    assert_eq!(
        answers.wire.slate().keys.len(),
        1,
        "the burst's key was kept, or the quiet one was not"
    );
}

/// The window the idle arm does not have: a byte typed before the question can land after
/// the burst's last empty poll and before the reader next blocks, with the arm already
/// pending, so the flush has to happen where the question opens.
#[test]
fn a_question_opened_after_a_burst_clears_what_was_typed_before() {
    let Pty { mut master, slave } = pty();
    let answers = answers(slave.try_clone().expect("a second handle"));
    answers.arm(&['y']).expect("armed");
    assert!(!answers.wire.slate().armed, "the arm was not pending");

    writeln!(master, "y").expect("the typed line");
    wait_readable(&slave);
    quiet(&answers);

    let mut watched = [nix::poll::PollFd::new(slave.as_fd(), PollFlags::POLLIN)];
    let queued = nix::poll::poll(&mut watched, PollTimeout::ZERO).expect("poll");
    assert!(answers.wire.slate().armed, "the question never opened");
    assert_eq!(queued, 0, "the typeahead survived the question opening");
}

/// A queue that cannot be cleared leaves no question to answer, and the reader's exit is
/// what ends a wait parked on it.
#[test]
fn a_question_that_cannot_be_opened_ends_the_reader() {
    struct Quiet;

    impl Source for Quiet {
        fn next(&mut self) -> io::Result<Option<Event>> {
            Ok(None)
        }
    }

    // Not a terminal, so the flush the question opens with is refused.
    let file = std::fs::File::open("/dev/null").expect("a descriptor that is no terminal");
    let answers = answers(file.try_clone().expect("a second handle"));
    answers.arm(&['y']).expect("pending, nothing flushed yet");
    let _keys = answers.wire.seen.subscribe();

    read(&answers.wire, file.as_fd(), file.as_fd(), &mut Quiet);

    assert_eq!(waited(&answers), Reply::Closed);
}

#[test]
fn a_stop_already_latched_is_visible_without_waiting() {
    let Pty { master: _m, slave } = pty();
    let answers = answers(slave);
    assert_eq!(
        answers.stopped(),
        None,
        "a turn nobody stopped reads as stopped"
    );

    answers.wire.pressed(key(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(answers.stopped(), Some(Reply::Interrupted));

    // An interrupt outranks a hangup, as in `wait`.
    answers.wire.gone();
    assert_eq!(answers.stopped(), Some(Reply::Interrupted));
}

#[test]
fn a_hangup_already_seen_is_visible_without_waiting() {
    let Pty { master: _m, slave } = pty();
    let answers = answers(slave);

    answers.wire.gone();

    assert_eq!(answers.stopped(), Some(Reply::Closed));
}

/// What was typed against the old frame is not an answer to the redrawn one, so a resize
/// ends the wait with the key forgotten, and the next arm starts clean.
#[test]
fn a_resize_wakes_a_wait_and_forgets_what_was_typed() {
    let Pty { master: _m, slave } = pty();
    let answers = answers(slave);
    answers.arm(&['y']).expect("armed");
    quiet(&answers);
    answers.wire.pressed(typed('y'));

    answers.wire.resized();

    assert_eq!(waited(&answers), Reply::Resized);
    assert!(
        answers.wire.slate().keys.is_empty(),
        "a key typed against the old frame survived the resize"
    );
    answers.arm(&['y']).expect("armed again");
    quiet(&answers);
    answers.wire.pressed(typed('y'));
    assert_eq!(waited(&answers), Reply::Key('y'));
}

#[test]
fn an_interrupt_outranks_a_resize() {
    let Pty { master: _m, slave } = pty();
    let answers = answers(slave);
    answers.arm(&['y']).expect("armed");
    quiet(&answers);
    answers.wire.resized();

    answers
        .wire
        .pressed(key(KeyCode::Char('c'), KeyModifiers::CONTROL));

    assert_eq!(waited(&answers), Reply::Interrupted);
}

/// The window between the draw and the arm: a resize there finds nothing armed, and must
/// still be waiting for the wait, or the frame it left stale is the one that is answered.
#[test]
fn a_resize_before_the_arm_still_wakes_the_wait() {
    let Pty { master: _m, slave } = pty();
    let answers = answers(slave);
    answers.wire.resized();
    answers.arm(&['y']).expect("armed");
    quiet(&answers);

    assert_eq!(waited(&answers), Reply::Resized);
}

/// Through the reader, which is what turns the terminal's resize into the wake.
#[test]
fn the_reader_reports_a_resize() {
    struct Resizes(Vec<io::Result<Option<Event>>>);

    impl Source for Resizes {
        fn next(&mut self) -> io::Result<Option<Event>> {
            self.0.remove(0)
        }
    }

    let Pty { master: _m, slave } = pty();
    let answers = answers(slave.try_clone().expect("a second handle"));
    let _keys = answers.wire.seen.subscribe();
    let mut source = Resizes(vec![
        Ok(Some(Event::Resize(80, 24))),
        Err(io::Error::from(io::ErrorKind::BrokenPipe)),
    ]);

    read(&answers.wire, slave.as_fd(), slave.as_fd(), &mut source);

    assert!(answers.wire.slate().resized, "the resize was dropped");
}

/// crossterm turns a `SIGWINCH` into an `Event::Resize` only inside `event::poll`, which the
/// reader calls only after its own poll returns: with no key typed, a reader that blocks on
/// the terminal for good never hears of the resize.
#[test]
fn a_reader_with_nothing_typed_still_looks_for_a_resize() {
    struct Looks(mpsc::Sender<()>);

    impl Source for Looks {
        fn next(&mut self) -> io::Result<Option<Event>> {
            self.0.send(()).expect("the test is listening");
            Ok(None)
        }
    }

    let Pty { master: _m, slave } = pty();
    let answers = answers(slave.try_clone().expect("a second handle"));
    let _keys = answers.wire.seen.subscribe();
    let (looked, looks) = mpsc::channel();
    let wire = Arc::clone(&answers.wire);
    thread::spawn(move || read(&wire, slave.as_fd(), slave.as_fd(), &mut Looks(looked)));

    // Twice: the first look is the reader's own, before it first blocks.
    for _ in 0..2 {
        looks
            .recv_timeout(Duration::from_secs(5))
            .expect("the reader never looked without a key");
    }
}

/// The wake itself: a wait already parked is ended by the resize, not only one that starts
/// after it.
#[test]
fn a_resize_wakes_a_wait_already_parked() {
    let Pty { master: _m, slave } = pty();
    let answers = answers(slave);
    answers.arm(&['y']).expect("armed");
    quiet(&answers);
    let (sent, received) = mpsc::channel();
    let waiting = answers.clone();
    thread::spawn(move || sent.send(waiting.wait()).expect("the test is listening"));
    thread::sleep(Duration::from_millis(100));

    answers.wire.resized();

    assert_eq!(
        received
            .recv_timeout(Duration::from_secs(5))
            .expect("the wait never returned"),
        Reply::Resized
    );
}
