use std::cell::Cell as Shared;
use std::fs::File;
use std::rc::Rc;

use nix::errno::Errno;
use sandbx_pty_fixture::{WINDOW, pty};

use super::*;

/// A pty slave, counting the writes that reach it: a draw that was attempted wrote.
struct Counted {
    pty: File,
    writes: Rc<Shared<usize>>,
}

impl Write for Counted {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes.set(self.writes.get() + 1);
        self.pty.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.pty.flush()
    }
}

impl AsFd for Counted {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.pty.as_fd()
    }
}

/// A terminal over a live pty, taken as `Screen::enter` takes stdout; the master whose
/// drop hangs it up; and the count of writes that reached it.
fn screen() -> (File, Terminal<Measured<Counted>>, Rc<Shared<usize>>) {
    let (master, slave) = pty();
    let writes = Rc::default();
    let counted = Counted {
        pty: slave,
        writes: Rc::clone(&writes),
    };

    let measured = Measured::new(counted).expect("a duplicate of the pty");
    let terminal = Terminal::new(measured).expect("a live pty is measured");

    (master, terminal, writes)
}

/// The pty's own `EIO` and not a size from anywhere else, `tput`'s included.
fn assert_unmeasured(failed: io::Result<()>) {
    let error = failed.expect_err("a hung-up pty was drawn on");
    assert_eq!(error.raw_os_error(), Some(Errno::EIO as i32), "{error}");
}

/// The whole of #269: a draw on a hung-up terminal fails at the size, before it writes.
#[test]
fn a_hung_up_terminal_is_not_drawn_on() {
    let (master, mut terminal, writes) = screen();
    let transcript = Transcript::new("a prompt", false);
    drop(master);

    let drawn = terminal.draw(|frame| draw(frame, &transcript, Hint::Running));

    assert_unmeasured(drawn.map(drop));
    assert_eq!(writes.get(), 0, "the draw was attempted");
}

/// And `finish`'s clear, which asks for the size itself rather than through a draw.
#[test]
fn a_hung_up_terminal_is_not_cleared() {
    let (master, mut terminal, writes) = screen();
    drop(master);

    assert_unmeasured(cleared(&mut terminal));
    assert_eq!(writes.get(), 0, "the clear was attempted");
}

/// The pair: a live pty is measured off its own descriptor, then cleared and drawn on,
/// so the two above are the hangup and not a backend that refuses everything.
#[test]
fn a_live_terminal_is_drawn_at_its_own_size() {
    let (_master, mut terminal, writes) = screen();
    let transcript = Transcript::new("a prompt", false);

    let size = terminal.size().expect("a live pty is measured");
    assert_eq!((size.width, size.height), WINDOW);

    cleared(&mut terminal).expect("a live pty is cleared");
    terminal
        .draw(|frame| draw(frame, &transcript, Hint::Running))
        .expect("a live pty is drawn on");
    assert!(writes.get() > 0, "nothing reached a live pty");
}
