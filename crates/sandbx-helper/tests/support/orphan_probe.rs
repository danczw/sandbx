//! Leaves the process group, then `exec`s itself from a second thread, and writes a canary if
//! still alive four seconds later. Test-only.
//!
//! The parent death signal is per thread and a new thread starts with it at 0, so the image
//! the thread execs carries none. A timed-out call returns no stdout, so it reports to a file.

use std::process::{Command, ExitCode};
use std::time::Duration;
use std::{env, fs, process, thread};

const CHILD_FLAG: &str = "--child";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if let [_, flag, report, canary] = args.as_slice()
        && flag == CHILD_FLAG
    {
        if fs::write(report, format!("STARTED pid={}", process::id())).is_err() {
            return ExitCode::FAILURE;
        }
        thread::sleep(Duration::from_secs(4));
        let _ = fs::write(canary, "alive");
        return ExitCode::SUCCESS;
    }

    let [_, report, canary] = args.as_slice() else {
        eprintln!("usage: orphan-probe <report-path> <canary-path>");
        return ExitCode::FAILURE;
    };

    if let Err(errno) = nix::unistd::setsid() {
        eprintln!("ORPHAN PROBE FAILED: setsid: {errno}");
        return ExitCode::FAILURE;
    }

    let (report, canary) = (report.clone(), canary.clone());
    let exec = thread::spawn(move || {
        use std::os::unix::process::CommandExt;

        // The workspace bans `Command::new`; what this probe execs is itself.
        #[allow(clippy::disallowed_methods)]
        Command::new("/proc/self/exe")
            .args([CHILD_FLAG, &report, &canary])
            .exec()
    });

    // Reached only if the `exec` failed: a success replaces this whole process.
    let error = exec
        .join()
        .map_or_else(|_| "panicked".to_owned(), |e| e.to_string());
    eprintln!("ORPHAN PROBE FAILED: exec: {error}");
    ExitCode::FAILURE
}
