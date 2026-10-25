//! A pty pair for tests that drive a real terminal, and the window it opens with.
//!
//! A dev-dependency only: nothing links this into a build that ships. It is a crate
//! rather than a `#[cfg(test)]` module because two crates drive the same fixture and a
//! `#[cfg(test)]` item is invisible across a crate boundary (#344).
//!
//! A `#[cfg(feature = ..)]` export from one of them instead would hit what
//! `context/guide-ci.md` records for a self dev-dependency, feature unification making
//! the two cases one: the other crate's dev edge turns the feature on in the single rlib
//! `--all-targets` builds, so production code naming the fixture passes clippy and the
//! whole suite and fails first in the release build, where no dev edge enables it. The
//! gated item also sits in that crate's public surface, which its `public-api.txt` —
//! generated without `--all-features` — does not record.

use std::fs::File;

/// The window every [`pty`] opens with, `(columns, rows)`: no terminal's default, so a
/// size read off anything but the pty under test does not match it.
pub const WINDOW: (u16, u16) = (33, 7);

/// A pty pair, and no controlling terminal: closing the master is then a hangup on the
/// slave rather than a `SIGHUP` that kills the test binary.
///
/// Echo off, so what the slave reads is only what the master wrote.
pub fn pty() -> (File, File) {
    use nix::pty::Winsize;
    use nix::sys::termios;

    let window = Winsize {
        ws_col: WINDOW.0,
        ws_row: WINDOW.1,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let pair = nix::pty::openpty(Some(&window), None).expect("a pty pair");

    let mut attrs = termios::tcgetattr(&pair.slave).expect("the pty's termios");
    attrs.local_flags.remove(termios::LocalFlags::ECHO);
    termios::tcsetattr(&pair.slave, termios::SetArg::TCSANOW, &attrs).expect("echo off");

    (File::from(pair.master), File::from(pair.slave))
}
