//! Leaves the process group, tries to clear its parent death signal, then writes a canary if
//! it is still alive two seconds later. Test-only.
//!
//! Run as the command, so PID 1 of its namespace: with both kill paths gone it outlives the
//! call. What `prctl` answered goes to a file, a timed-out call returning no stdout.

fn main() -> std::process::ExitCode {
    let (Some(report), Some(canary)) = (std::env::args().nth(1), std::env::args().nth(2)) else {
        eprintln!("usage: pdeathsig-probe <report-path> <canary-path>");
        return std::process::ExitCode::FAILURE;
    };

    let left =
        nix::unistd::setsid().map_or_else(|errno| format!("SETSID {errno}"), |_| String::new());

    let answer = match nix::sys::prctl::set_pdeathsig(None) {
        Ok(()) => "PDEATHSIG CLEARED".to_owned(),
        Err(errno) => format!("PDEATHSIG REFUSED {}", errno as i32),
    };

    if std::fs::write(&report, format!("{left}{answer}")).is_err() {
        return std::process::ExitCode::FAILURE;
    }

    std::thread::sleep(std::time::Duration::from_secs(2));
    let _ = std::fs::write(&canary, "alive");

    std::process::ExitCode::SUCCESS
}
