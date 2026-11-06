//! Does a name the allowlist does not hold fail to resolve, and does one it holds still work?
//!
//! The resolver half of the enforcement suite; `enforcement.rs` states the kernel floor all of
//! these run on. Every name here is one this host's own `/etc/hosts` lists, and the denial and
//! the no-flag test also insist its line maps it: a name left to `dns` fails in any sandbox,
//! flag or not, so a denial of it is a run that was offline anyway.
#![cfg(all(feature = "sandbox-integration", target_os = "linux"))]

use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::process::Output;
use std::thread::JoinHandle;
use std::time::Duration;
use std::{fs, thread};

use sandbx_core::SandboxPolicy;
use sandbx_helper_fixture::{allow_probe, runtime_paths, vetted};

fn helper() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_sandbx-helper"))
}

fn run(policy: &SandboxPolicy, program: &str, args: &[&str]) -> Output {
    sandbx_helper_fixture::run(helper(), policy, program, args)
}

/// The names sandbx's own hosts file writes, which prove nothing about the allowlist: a name
/// from this set resolves whether the policy asked for it or not.
const LOOPBACK_NAMES: [&str; 3] = ["localhost", "ip6-localhost", "ip6-loopback"];

/// The one sysctl under which bounding resolution cannot work at all, read rather than inferred.
const USERNS_RESTRICTION: &str = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";

/// Whether this host forbids the mounts, in which case the six tests below assert nothing.
/// Reads the sysctl rather than catching the `EACCES` it produces, since an errno guard
/// would skip on a genuine regression too — the one that unbounds every name silently. Set,
/// the kernel lets `unshare` succeed and then denies `CAP_SYS_ADMIN` inside the new
/// namespace, so `helper::resolver` refuses the run. Same host property as
/// `enforcement.rs`'s `bounding_set_is_droppable`, same root exemption.
fn host_forbids_the_mounts() -> bool {
    use std::os::unix::fs::MetadataExt as _;

    // The restriction covers *unprivileged* userns only, so root holds `CAP_SYS_ADMIN` in the
    // new namespace regardless — skipping under `sudo cargo test` would lose coverage on the
    // one host that has it. Off `/proc/self`'s owner since `libc::geteuid` is `unsafe`.
    let root = fs::metadata("/proc/self")
        .map(|proc_self| proc_self.uid() == 0)
        .unwrap_or(false);

    let restricted = !root
        && fs::read_to_string(USERNS_RESTRICTION)
            .is_ok_and(|value| value.trim().parse::<u32>().is_ok_and(|flag| flag != 0));

    if restricted {
        eprintln!(
            "SKIPPED: {USERNS_RESTRICTION} is set, so this host denies CAP_SYS_ADMIN inside an \
             unprivileged user namespace and --allow-dns cannot be enforced on it at all. The \
             claim is untested here; see SECURITY.md."
        );
    }

    restricted
}

/// A name of `names` this host's `/etc/hosts` lists, and a listener on an address it resolves
/// to. Derived, not written down — the one such name on a developer machine is the machine's
/// own hostname, and hard-coding either would pass on one host and fail on the next.
/// Looked for up to [`ATTEMPTS`] times, since a host rewriting the file leaves it empty for a
/// moment and a look landing there finds no name. A test under [`retried_across_rewrites`]
/// takes [`one_look_listener`] instead, so the wrapper's one retry covers the look too.
fn local_listener(payload: &'static str, names: Names) -> LocalListener {
    (0..ATTEMPTS)
        .find_map(|retry| {
            if retry > 0 {
                thread::sleep(REWRITE_PAUSE);
            }
            one_look_listener(payload, names)
        })
        .expect(NO_NAME)
}

/// Why no test here can run without a [`local_listener`] name.
const NO_NAME: &str = "no name of the kind this test takes in /etc/hosts resolves to an address \
                       it can bind, so it has nothing to resolve. For a test needing a name the \
                       file itself maps, a hostname line with no address is enough (#472)";

/// One look for [`local_listener`]'s name, `None` when it finds none.
fn one_look_listener(payload: &'static str, names: Names) -> Option<LocalListener> {
    let hosts = fs::read_to_string("/etc/hosts").ok()?;
    let (name, address, listener) = bindable_name(&hosts, names)?;

    let accepting = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            use std::io::Write;
            let _ = stream.write_all(payload.as_bytes());
        }
    });

    Some(LocalListener {
        name,
        address,
        accepting,
    })
}

/// Which of `/etc/hosts`'s names [`bindable_name`] may take.
#[derive(Clone, Copy, PartialEq)]
enum Names {
    /// Any but a loopback name, on a line with no address too, its first field taken for the
    /// address all the same. A runner writes its hostname that way before it knows its IP
    /// (#472), leaving the name to `dns`: enough only where the helper resolves it, before the
    /// unshare.
    Listed,
    /// A non-loopback name its own line maps to the address it resolves to, so it resolves
    /// with no nameserver.
    Mapped,
    /// A loopback name its own line maps, as for [`Names::Mapped`].
    Loopback,
}

/// One look through `hosts` for [`local_listener`]'s name, and the listener it bound.
fn bindable_name(hosts: &str, names: Names) -> Option<(String, SocketAddr, TcpListener)> {
    hosts
        .lines()
        .map(|line| line.split('#').next().unwrap_or_default())
        .flat_map(|line| {
            let mut fields = line.split_whitespace();
            let listed = fields.next().and_then(|field| field.parse::<IpAddr>().ok());
            fields.map(move |name| (name, listed))
        })
        .filter(|(name, listed)| match names {
            Names::Listed => !LOOPBACK_NAMES.contains(name),
            Names::Mapped => listed.is_some() && !LOOPBACK_NAMES.contains(name),
            Names::Loopback => listed.is_some() && LOOPBACK_NAMES.contains(name),
        })
        .flat_map(|(name, listed)| {
            let addresses = (name, 0u16).to_socket_addrs().into_iter().flatten();
            addresses
                .filter(move |address| names == Names::Listed || listed == Some(address.ip()))
                .map(move |address| (name, address))
        })
        .find_map(|(name, address)| {
            TcpListener::bind(address).ok().map(|listener| {
                let port = listener
                    .local_addr()
                    .expect("a bound listener has an address");
                (name.to_string(), port, listener)
            })
        })
}

/// How many times a look or a test reruns while the host keeps rewriting `/etc/hosts`.
const ATTEMPTS: usize = 3;

/// Between attempts, and longer than a rewrite holds the file empty: an attempt that failed
/// fast returns inside the window that failed it, and an unpaused retry would land there too.
const REWRITE_PAUSE: Duration = Duration::from_millis(100);

/// The host's `/etc/hosts` and its inode and ctime, two reads rather than one instant, so a
/// rename between them only reads as a change, never hides one. `None` while missing or empty —
/// the state a rewrite passes through, never one a host leaves it in. The bytes alone miss a
/// rewrite to the same bytes, which still empties the file for a moment: the ctime catches
/// that, being the one timestamp user space cannot set back, and the inode catches a rename
/// over the file. Before 6.13's multigrain timestamps the ctime is one clock tick coarse, so
/// a second rewrite inside the tick of the first still slips past.
fn hosts_snapshot() -> Option<(String, u64, i64, i64)> {
    use std::os::unix::fs::MetadataExt as _;

    let body = fs::read_to_string("/etc/hosts")
        .ok()
        .filter(|body| !body.is_empty())?;
    let meta = fs::metadata("/etc/hosts").ok()?;

    Some((body, meta.ino(), meta.ctime(), meta.ctime_nsec()))
}

/// Run a test whose verdict rests on a lookup in the host's `/etc/hosts` succeeding — in
/// `helper::resolver` rendering the bound file, or in the command reading the host's own —
/// and fail it only on an attempt the file held still across. A rewrite empties the file
/// for a moment, and a lookup landing there misses and reads as the claim failing.
///
/// A pass stands whatever the file did. Only for tests that write nothing: a run whose own
/// write reached the host would change the file, and read here as a rewrite to retry.
fn retried_across_rewrites(mut attempt: impl FnMut() -> Result<(), String>) {
    for retry in 0..ATTEMPTS {
        if retry > 0 {
            thread::sleep(REWRITE_PAUSE);
        }

        let before = hosts_snapshot();
        let Err(failure) = attempt() else {
            return;
        };
        if before.is_some() && hosts_snapshot() == before {
            panic!("{failure}");
        }
    }

    eprintln!(
        "SKIPPED: the host rewrote /etc/hosts during each of {ATTEMPTS} failed attempts, so a \
         name that failed to resolve may have been missing from the file itself. The claim is \
         untested on this run."
    );
}

/// Whatever decides whether the command's `files` lookup can match, so a failure names a
/// cause rather than only the `EAI_AGAIN` every cause ends in.
fn host_resolution_facts() -> String {
    let hosts = Path::new("/etc/hosts");
    let file_type = fs::symlink_metadata(hosts).map(|meta| meta.file_type());
    let canonical = fs::canonicalize(hosts);
    let switch = fs::read_to_string("/etc/nsswitch.conf").unwrap_or_default();

    format!(
        "/etc/hosts {file_type:?}, canonical {canonical:?}; nsswitch.conf {:?}",
        resolution_databases(&switch),
    )
}

/// What [`local_listener`] found and bound, and the thread answering on it.
struct LocalListener {
    name: String,
    address: SocketAddr,
    accepting: JoinHandle<()>,
}

/// Unblock a listener thread nothing connected to, so the test does not leak it.
fn drain(address: SocketAddr, accepting: JoinHandle<()>) {
    let _ = TcpStream::connect(address);
    let _ = accepting.join();
}

fn probe(policy: SandboxPolicy, args: &[&str]) -> Output {
    let probe = env!("CARGO_BIN_EXE_sandbx-resolver-probe");
    let policy = allow_probe(runtime_paths(policy), probe);

    run(&policy, probe, args)
}

/// A config file's directives, comments stripped: sandbx's own files say in a comment what
/// they leave out, and matching the whole body would read the explanation as the thing.
fn directives(body: &str) -> String {
    body.lines()
        .filter_map(|line| line.split('#').next())
        .collect()
}

/// The `nsswitch.conf` lines that decide how a name resolves, which are the only ones bounding
/// resolution may touch: a `passwd` or `group` line is the host's and is asserted elsewhere.
fn resolution_databases(body: &str) -> Vec<&str> {
    body.lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter(|line| {
            let database = line.split(':').next().unwrap_or_default().trim();
            database == "hosts" || database == "networks"
        })
        .collect()
}

/// The names a hosts file maps, whichever addresses it maps them to.
fn mapped_names(hosts: &str) -> Vec<String> {
    hosts
        .lines()
        .map(|line| line.split('#').next().unwrap_or_default())
        .flat_map(|line| line.split_whitespace().skip(1))
        .map(str::to_string)
        .collect()
}

/// The claim, whole: the name resolves, the address it resolves to is reached, and the policy
/// grants no read on `/etc` at all — which is the one flag that makes a policy smaller.
#[test]
fn an_allowlisted_name_resolves_and_is_reached() {
    if host_forbids_the_mounts() {
        return;
    }

    retried_across_rewrites(|| {
        let Some(LocalListener {
            name,
            address,
            accepting,
        }) = one_look_listener("ALLOWLISTED-NAME-ANSWERED", Names::Listed)
        else {
            return Err(NO_NAME.into());
        };

        let output = probe(
            SandboxPolicy::default()
                .allow_dns(&name)
                .allow_network_port(address.port()),
            &["connect", &format!("{name}:{}", address.port())],
        );

        drain(address, accepting);

        if !output.status.success() {
            return Err(format!(
                "an allowlisted name ({name}) could not be reached, so the flag grants \
                 nothing: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("ALLOWLISTED-NAME-ANSWERED"),
            "the name resolved but the connection read nothing from the listener"
        );
        Ok(())
    });
}

/// The denial. `local_listener` resolved the name in this process out of the host's own file,
/// so it resolves outside the sandbox with no nameserver, and the port it answers on is
/// allowlisted.
#[test]
fn a_name_the_allowlist_does_not_hold_does_not_resolve() {
    if host_forbids_the_mounts() {
        return;
    }

    let LocalListener {
        name,
        address,
        accepting,
    } = local_listener("SECRET-BEHIND-THE-NAME", Names::Mapped);

    // `localhost` as the one allowlisted name: it bounds resolution without bounding it to
    // the name under test.
    let policy = SandboxPolicy::default()
        .allow_dns("localhost")
        .allow_network_port(address.port());

    let control = probe(policy.clone(), &["resolve", "localhost"]);
    let denied = probe(policy, &["connect", &format!("{name}:{}", address.port())]);

    drain(address, accepting);

    assert!(
        control.status.success(),
        "a bounded resolver could resolve nothing at all, so the denial below says nothing: {}",
        String::from_utf8_lossy(&control.stderr)
    );
    assert!(
        !denied.status.success(),
        "{name} resolved though the allowlist never named it, so the allowlist bounds \
         nothing and every name the host can resolve is still reachable"
    );
    assert!(
        !String::from_utf8_lossy(&denied.stdout).contains("SECRET-BEHIND-THE-NAME"),
        "read from an address only a name outside the allowlist leads to"
    );
}

/// The mechanism, from the command's side: the `/etc/hosts` it reads is sandbx's own, holding
/// the allowlisted name and nothing else the host's file maps.
#[test]
fn the_hosts_file_the_command_reads_holds_only_allowlisted_names() {
    if host_forbids_the_mounts() {
        return;
    }

    retried_across_rewrites(|| {
        let Some(LocalListener {
            name,
            address,
            accepting,
        }) = one_look_listener("UNUSED", Names::Listed)
        else {
            return Err(NO_NAME.into());
        };
        drain(address, accepting);

        let output = probe(
            SandboxPolicy::default().allow_dns(&name),
            &["read", "/etc/hosts"],
        );

        let seen = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "the command could not read /etc/hosts under --allow-dns, so resolution has no \
             source to read: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        // The one assertion here a truncating rewrite can fail: the helper resolves the name
        // off the host's file to render the bound one, and an empty look renders it unmapped.
        // A rewrite that unlinks the file has the helper refuse the run as `absent`, unretried.
        if !(seen.contains(&name) && seen.contains(&address.ip().to_string())) {
            return Err(format!(
                "the hosts file does not map the allowlisted name to the address it resolved \
                 to: {seen}"
            ));
        }

        for mapped in mapped_names(&seen) {
            assert!(
                mapped == name || LOOPBACK_NAMES.contains(&mapped.as_str()),
                "the hosts file the command reads maps {mapped}, which is neither the \
                 allowlisted name nor a loopback name — the host's own file is still visible"
            );
        }
        Ok(())
    });
}

/// What `ruleset::opened::open_grant` compares a granted path against. A bind whose source
/// had been unlinked reads back from `/proc/self/fd` with `" (deleted)"` appended, so
/// every grant reaching one of these three files would be refused. `/etc` and not
/// `/etc/hosts`: a grant naming a bound file exactly is refused for its pin
/// (`SandboxPolicy::grant_bound_by_resolver`), and `/etc`'s own inode is what a grant above
/// the bind is pinned to.
#[test]
fn a_bound_file_reads_back_under_the_path_it_was_mounted_on() {
    if host_forbids_the_mounts() {
        return;
    }

    let LocalListener {
        name,
        address,
        accepting,
    } = local_listener("UNUSED", Names::Listed);
    drain(address, accepting);

    // `/proc` read is the probe's own need, `/proc/self/fd` being where the kernel answers.
    let policy = SandboxPolicy::default()
        .allow_dns(&name)
        .allow_read(vetted("/proc"))
        .allow_read(vetted("/etc"));

    let output = probe(policy, &["fdpath", "/etc/hosts"]);

    assert!(
        output.status.success(),
        "the probe could not read a path back for the bound hosts file: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "/etc/hosts",
        "the bound hosts file reads back under another path, so every grant naming it is \
         compared against a spelling the policy never carried"
    );
}

/// glibc's `dns` source has to be gone, not merely unreachable: a nameserver that becomes
/// reachable later would answer for every name, and the allowlist would bound nothing.
#[test]
fn the_command_is_left_no_dns_source_and_no_nameserver() {
    if host_forbids_the_mounts() {
        return;
    }

    let LocalListener {
        name,
        address,
        accepting,
    } = local_listener("UNUSED", Names::Listed);
    drain(address, accepting);

    let policy = SandboxPolicy::default().allow_dns(&name);
    let nsswitch = probe(policy.clone(), &["read", "/etc/nsswitch.conf"]);
    let resolv = probe(policy, &["read", "/etc/resolv.conf"]);

    let switch = String::from_utf8_lossy(&nsswitch.stdout);
    assert!(
        nsswitch.status.success(),
        "the command could not read /etc/nsswitch.conf, so glibc falls back to its built-in \
         default, which includes the dns source: {}",
        String::from_utf8_lossy(&nsswitch.stderr)
    );
    for line in resolution_databases(&switch) {
        assert!(
            !line.contains("dns"),
            "the nsswitch.conf the command reads keeps a dns source: {line:?}"
        );
    }

    // Resolution is all that may be bounded: a `passwd` or `group` line reaching `systemd`,
    // `sss` or LDAP is how a command resolves its own uid to a name.
    let host = fs::read_to_string("/etc/nsswitch.conf").unwrap_or_default();
    let kept = host
        .lines()
        .filter(|line| !line.trim_start().starts_with('#') && line.contains(':'))
        .filter(|line| resolution_databases(line).is_empty());

    for line in kept {
        assert!(
            switch.contains(line),
            "the host configures {line:?} and the command no longer sees it, so bounding \
             resolution took a lookup that is not a name with it"
        );
    }

    // Skipped where the host's `/etc/resolv.conf` is absent or a symlink, which is where
    // `helper::resolver` and `ruleset::rights` leave the command none to read: a resolver has
    // no file to take a nameserver out of either, and the two below carry the bound.
    if resolv.status.success() {
        let conf = String::from_utf8_lossy(&resolv.stdout);
        assert!(
            !directives(&conf).contains("nameserver"),
            "the resolv.conf the command reads names a nameserver, which musl asks for \
             every name: {conf}"
        );
    }
}

/// The read-only remount, which is the whole reason for the second `mount` call: with write
/// granted over `/etc`, appending one line would add a name the operator never allowlisted.
#[test]
fn the_hosts_file_is_not_writable_under_a_write_grant() {
    if host_forbids_the_mounts() {
        return;
    }

    let LocalListener {
        name,
        address,
        accepting,
    } = local_listener("UNUSED", Names::Listed);
    drain(address, accepting);

    let scratch = tempfile::tempdir().expect("a temporary directory");
    let writable = scratch.path().join("writable");
    fs::write(&writable, b"").expect("an empty file to append to");

    let policy = SandboxPolicy::default()
        .allow_dns(&name)
        .allow_write(vetted("/etc"))
        .allow_write(vetted(scratch.path()));

    let control = probe(policy.clone(), &["write", &writable.display().to_string()]);
    let refused = probe(policy, &["write", "/etc/hosts"]);

    assert!(
        control.status.success(),
        "the write grant wrote nothing at all, so the refusal below says nothing: {}",
        String::from_utf8_lossy(&control.stderr)
    );
    assert!(
        !refused.status.success(),
        "a command with write over /etc appended to the hosts file, so it can add any name \
         it likes to its own allowlist"
    );
}

/// The namespace is the command's own: a run that mutated the host's `/etc` would bound
/// this command's names by changing every other process's. The one test here that runs its
/// body where the mounts are forbidden, so both branches have to assert — an early return
/// would report `ok` having checked only that a refused run changes nothing, which a
/// deleted feature also does. The restricted branch pins the refusal instead, the only
/// assertion anywhere on `helper::resolver`'s `EACCES` path.
#[test]
fn the_host_etc_survives_a_bounded_run() {
    let LocalListener {
        name,
        address,
        accepting,
    } = local_listener("UNUSED", Names::Listed);
    drain(address, accepting);

    let before = fs::read_to_string("/etc/hosts").expect("the host's hosts file");

    let policy = SandboxPolicy::default()
        .allow_dns(&name)
        .allow_write(vetted("/etc"))
        .allow_network_port(address.port());
    let output = probe(policy, &["write", "/etc/hosts"]);

    let after = fs::read_to_string("/etc/hosts").expect("the host's hosts file");
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Never retried: a change to the host's file is the very thing this asserts against, and
    // a retry would read an escape as a host rewrite.
    assert_eq!(
        before, after,
        "a bounded run changed the host's /etc/hosts, so the mounts are propagating out of \
         the command's namespace — unless something on the host rewrote it during the run, \
         which a rerun tells apart"
    );
    assert!(
        !output.status.success(),
        "the command appended a name of its own to /etc/hosts: {stderr}"
    );

    if host_forbids_the_mounts() {
        assert!(
            stderr.contains("CAP_SYS_ADMIN"),
            "this host denies CAP_SYS_ADMIN inside an unprivileged user namespace, so the run \
             should have been refused saying so — any other failure here means the refusal \
             names something else, or that resolution ran unbounded: {stderr}"
        );
        return;
    }

    assert!(
        stderr.contains("WRITE DENIED"),
        "the command never reached its write, so nothing here says the host's /etc survived \
         a run that was bounded rather than refused: {stderr}"
    );
}

/// The flag is opt-in: without it there is no mount namespace and no rendered hosts file, so
/// a command resolves exactly what it resolved before this existed. `localhost` stands in on a
/// host whose file maps no name of its own: with no flag nothing is rendered, and comparing
/// the file the command reads with the host's is what tells the two apart.
#[test]
fn a_run_without_the_flag_resolves_as_it_did_before() {
    retried_across_rewrites(|| {
        let listed = fs::read_to_string("/etc/hosts").unwrap_or_default();
        let Some((name, address, _listener)) = bindable_name(&listed, Names::Mapped)
            .or_else(|| bindable_name(&listed, Names::Loopback))
        else {
            return Err(NO_NAME.into());
        };

        let policy = SandboxPolicy::default()
            .allow_read(vetted("/etc"))
            .allow_network_port(address.port());

        let resolved = probe(policy.clone(), &["resolve", &name]);
        let facts = host_resolution_facts();
        let hosts = probe(policy, &["read", "/etc/hosts"]);
        let host_file = fs::read_to_string("/etc/hosts").unwrap_or_default();

        if !resolved.status.success() {
            return Err(format!(
                "a run with no --allow-dns could not resolve {name} out of /etc/hosts, so the \
                 flag narrowed a policy that never asked for it: {}\nhost as the resolve \
                 ended: {facts}\n/etc/hosts read in the sandbox just after: {}{}\nthe \
                 host's own /etc/hosts just after that: {host_file}",
                String::from_utf8_lossy(&resolved.stderr),
                String::from_utf8_lossy(&hosts.stdout),
                String::from_utf8_lossy(&hosts.stderr)
            ));
        }
        if String::from_utf8_lossy(&hosts.stdout) != host_file {
            return Err(
                "a run with no --allow-dns reads a hosts file that is not the host's".into(),
            );
        }
        Ok(())
    });
}
