//! Leaves the process group, then `exec`s itself from a second thread, and writes a canary if
//! still alive four seconds later. Test-only.
//!
//! The parent death signal is per thread and a new thread starts with it at 0, so the image
//! the thread execs carries none. A timed-out call returns no stdout, so it reports to a file.

const CHILD_FLAG: &str = "--child";

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if let [_, flag, report, canary] = args.as_slice()
        && flag == CHILD_FLAG
    {
        if std::fs::write(report, format!("STARTED pid={}", std::process::id())).is_err() {
            return std::process::ExitCode::FAILURE;
        }
        std::thread::sleep(std::time::Duration::from_secs(4));
        let _ = std::fs::write(canary, "alive");
        return std::process::ExitCode::SUCCESS;
    }

    let [_, report, canary] = args.as_slice() else {
        eprintln!("usage: orphan-probe <report-path> <canary-path>");
        return std::process::ExitCode::FAILURE;
    };

    if let Err(errno) = nix::unistd::setsid() {
        eprintln!("ORPHAN PROBE FAILED: setsid: {errno}");
        return std::process::ExitCode::FAILURE;
    }

    let (report, canary) = (report.clone(), canary.clone());
    let exec = std::thread::spawn(move || {
        use std::os::unix::process::CommandExt;

        // The workspace bans `Command::new`; what this probe execs is itself.
        #[allow(clippy::disallowed_methods)]
        std::process::Command::new("/proc/self/exe")
            .args([CHILD_FLAG, &report, &canary])
            .exec()
    });

    // Reached only if the `exec` failed: a success replaces this whole process.
    let error = exec
        .join()
        .map_or_else(|_| "panicked".to_owned(), |e| e.to_string());
    eprintln!("ORPHAN PROBE FAILED: exec: {error}");
    std::process::ExitCode::FAILURE
}
