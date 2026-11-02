//! A pty pair for tests that drive a real terminal, and the window it opens with.
//!
//! A dev-dependency only: nothing links this into a build that ships. It is a crate
//! rather than a `#[cfg(test)]` module because two crates drive the same fixture and a
//! `#[cfg(test)]` item is invisible across a crate boundary (#344).
//!
//! A `#[cfg(feature = ..)]` export from one of them instead would diverge between the two
//! builds — on in the rlib `--all-targets` builds, off in the release build — so
//! production code naming the fixture would pass clippy and the whole suite and fail
//! first at release. `context/guide-ci.md` records that for a *self* dev-dependency;
//! feature unification makes the cross-crate case the same one. It would also put the
//! fixture in that crate's public surface, where a `public-api.txt` generated without
//! `--all-features` does not record it.

use std::fs::File;

/// The window every [`pty`] opens with: no terminal's default, so a size read off anything
/// but the pty under test does not match it.
pub const WINDOW: Window = Window {
    columns: 33,
    rows: 7,
};

/// A terminal window's size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    /// Width, in cells.
    pub columns: u16,
    /// Height, in cells.
    pub rows: u16,
}

/// The two ends of a [`pty`].
#[derive(Debug)]
pub struct Pty {
    /// The side a test writes the operator's keys to; dropping it hangs up `slave`.
    pub master: File,
    /// The side handed to the code under test as its terminal.
    pub slave: File,
}

/// A pty pair, and no controlling terminal: closing the master is then a hangup on the
/// slave rather than a `SIGHUP` that kills the test binary.
///
/// Echo off, so what the slave reads is only what the master wrote.
pub fn pty() -> Pty {
    use nix::pty::Winsize;
    use nix::sys::termios;

    let window = Winsize {
        ws_col: WINDOW.columns,
        ws_row: WINDOW.rows,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let pair = nix::pty::openpty(Some(&window), None).expect("a pty pair");

    let mut attrs = termios::tcgetattr(&pair.slave).expect("the pty's termios");
    attrs.local_flags.remove(termios::LocalFlags::ECHO);
    termios::tcsetattr(&pair.slave, termios::SetArg::TCSANOW, &attrs).expect("echo off");

    Pty {
        master: File::from(pair.master),
        slave: File::from(pair.slave),
    }
}
