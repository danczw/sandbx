# Security Policy

sandbx confines what an AI agent can do, so a weakness in that boundary is a bug
in the product. What is claimed, what is not, and how to report what it missed.

## Reporting a vulnerability

**Use [private vulnerability reporting](https://github.com/danczw/sandbx/security/advisories/new).**
No public issue for a sandbox escape.

First response within a week. Personal project: no security team, no bounty. You
get an honest assessment, credit if you want it, a public advisory once a fix
ships. Something already under *Known weaknesses* gets the issue number.

## Supported versions

| version | supported |
|---------|-----------|
| latest pre-release | yes |
| anything older | no |

Highest version number on the
[releases page](https://github.com/danczw/sandbx/releases), never publication
order — pre-1.0 every tag is a pre-release, so GitHub's own "latest" link stays
empty. No backports: fixes ship in the next tag.

## What sandbx claims to enforce

On Linux 6.10+ with unprivileged user namespaces available, for a command run
through `SandboxedCommand`:

| control | mechanism | covers |
|---------|-----------|--------|
| filesystem | Landlock, ABI 5 minimum, negotiated up to the newest ABI the kernel enforces *in full*, hard-required at that level | reads, writes, execution by path, granted separately |
| entry point | SHA-256 over the descriptor the helper execs, when `--pin-sha256` names a digest | the bytes of the one program sandbx executes, not what it spawns — hashed through the descriptor it then execs, so no path is re-resolved between check and `execve`. A mismatch refuses the run before anything executes, as does an image a pin cannot cover: a `#!` script, or a program granted execute but not read ([context/decision-pinned-entry-point.md](context/decision-pinned-entry-point.md)) |
| network | an empty network namespace; or, with a port allowlist, Landlock TCP port rules plus seccomp denial of UDP, raw sockets, non-TCP stream protocols, IP-tunnelling families, `TCP_ULP` conversion, TCP Fast Open | IP egress and abstract unix sockets when network is withheld; IP connect and bind narrowed to the allowlisted TCP ports when granted per port |
| name resolution | with `--allow-dns NAME`: the files every resolver reads — a `hosts` sandbx resolved before the command started, `nsswitch.conf` with no `dns` source, a nameserver-less `resolv.conf` — bind-mounted read-only over `/etc` in the command's own mount namespace | which names resolve, nothing about which hosts are reachable. An unlisted name does not resolve, immediately rather than by timeout, and no nameserver is left to ask instead — see *[What `--allow-dns` bounds](#what---allow-dns-bounds)* |
| unix sockets | seccomp-bpf on `socket(AF_UNIX)` and on a connectionless `socketpair(AF_UNIX)`, plus Landlock `ResolveUnix` on every granted path where the kernel handles it — ABI V9, Linux 7.1 | whether the command may open a unix socket that reaches anything outside itself: one boolean, never a chosen path. A connected `socketpair` is left alone and is not an exception — both halves are inside the sandbox, and neither can be re-aimed at a host socket. *Which* pathname socket it may dial is bounded by the filesystem policy at V9 only; below V9 nothing bounds it, and a socket whose path the command knows is reachable with no grant naming it — see *[What sandbx does not claim](#what-sandbx-does-not-claim)* |
| environment | `env_clear` plus a name allowlist on the policy (`SandboxPolicy::allow_env`), then the constants `SandboxPolicy::imposed_env` sets | which variables the command *inherits*; everything unnamed is dropped, at every spawn stage, so a secret in the harness's own environment does not cross. Not the whole of what it holds: `--dns-over-tcp` imposes `RES_OPTIONS=use-vc` with no `--allow-env` naming it, so the child's environment is the allowlist plus a set of compile-time constants. `permits_env` — allowlisted or imposed — is the predicate `spawn::command` builds and the helper's inherited-environment check asks |
| syscalls | seccomp-bpf | a denylist — process inspection, namespace manipulation, mounting, loading code into the kernel, the keyring, `io_uring`, `userfaultfd`, `memfd_create`, whole-host state — plus a foreign architecture killed outright. See *[The syscall denylist](#the-syscall-denylist)* |
| process state | prctl, rlimit, capset | `no_new_privs`, `RLIMIT_CORE=0`, empty effective/permitted/inheritable/ambient capability sets (bounding set best-effort — see below) |
| process lifetime | PID namespace + `PR_SET_PDEATHSIG` | every process the command spawned is killed when the call ends, including one that called `setsid` |
| process signalling | PID namespace | a command cannot signal, or even name, a process outside its own namespace |

### What `--allow-dns` bounds

- **Resolution, not connection.** An IP literal, or an address already held,
  reaches an allowlisted port as before.
- **It grants no path**, so no `--allow-read /etc`: the read rules are on the
  bound files.
- **Every `nsswitch.conf` database but `hosts` and `networks` stays as the host
  had it** — an account in `systemd`, `sss` or LDAP still looks up inside the
  sandbox. Those two rewritten to `files` leave glibc no `dns` source.
- **Four shapes refuse the run**, each leaving a reachable nameserver that would
  answer for every name: `--dns-over-tcp`, bare `--allow-network`,
  `--allow-unix-sockets` (nscd, asked before `nsswitch.conf`), or 53 in the port
  list. Decided on the policy itself, so an embedder meets them too. A fifth is
  CLI-only: a name allowlist with no IP egress.
- **A symlinked `/etc/hosts` or `/etc/nsswitch.conf` refuses the run.** A bind
  resolves the link, leaving the link itself replaceable under a write grant.
  `resolv.conf` is exempt — a forged one names a nameserver no bounded policy can
  reach — and a symlinked one is bound over its target with no read rule, so the
  command reads `EACCES` there unless another grant reaches it.
- **Needs a host where an unprivileged user namespace may mount.** Under Ubuntu's
  `kernel.apparmor_restrict_unprivileged_userns=1` the run is refused rather than
  left resolving every name.

Which file carries which half of that, and why each refusal is a refusal:
[context/guide-sandboxing.md](context/guide-sandboxing.md) and
[context/decision-egress-proxy.md](context/decision-egress-proxy.md).

### The syscall denylist

Beyond the network calls a port allowlist must shut, seccomp-bpf denies:

- process inspection, and handles on other processes — `pidfd_getfd` steals an
  open descriptor, and `perf_event_open` is tracing infrastructure, a known
  side-channel surface;
- namespace manipulation, and *creation* on every route: `clone` filtered per
  `CLONE_NEW*` flag, `clone3` answers `ENOSYS`;
- reshaping the filesystem under Landlock: mounting by name (`mount`) and by
  descriptor (`open_tree`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`,
  `fspick`), `mount_setattr`, which would clear `MS_RDONLY` on a mount already
  there, and `umount2`, `pivot_root` and `chroot`, which move the tree out from
  under rules bound to it;
- loading code into the kernel (the module calls, `bpf`, and `kexec_load`, which
  loads a whole one), the keyring, `userfaultfd`, `memfd_create`;
- `io_uring`, which runs operations without issuing them;
- whole-host state: `reboot`, `swapon`, `swapoff`.

A foreign architecture is killed outright rather than refused per call — i386 on
`x86_64`, AArch32 on `aarch64` — its syscall numbers mean something else. The x32
ABI is refused wholesale, and needs its own rule because it shares the
architecture the filter gates on.

### Five properties that matter as much as the list

- **It fails closed.** A kernel that cannot enforce the baseline is refused, and
  so is a ruleset only *partly* applied: partial application is a hole, not a
  reduced sandbox. Negotiation walks down from the latest ABI to the ABI 5 floor
  for the newest the kernel takes in full; nothing short of full enforcement is
  accepted.
- **It is default-deny — at the library level, which is the level that is a
  boundary.** A `SandboxPolicy` grants nothing until something is added,
  environment included: `SandboxPolicy::default()` passes zero variables, and
  nothing an embedder constructs inherits a CLI default.

  The CLI is the convenience layer, and opts into three things — read on the
  system binaries and libraries, a handful of environment variables, and, with
  *no* path flag, read **and write** on the working directory, which any path
  flag replaces rather than adds to. That derived default refuses six shapes of
  working directory outright rather than deriving a narrower root, and the record
  lists them
  ([context/decision-default-policy.md](context/decision-default-policy.md)).
  What the write grant means for files executed *later* is a non-claim below.
- **Grants do not widen each other, with one named exception.** Read does not
  confer execute; write confers neither read nor execute — a write-only drop
  directory stays unreadable, on both enforcement layers. That is per *grant*: the
  CLI deliberately makes two for `--allow-write` (see *Not vulnerabilities*), the
  library keeps the axes separate. The exception is `allow_read_execute`, which
  grants both, a program needing execute on the binary *and* read on the libraries
  its loader pulls in; the asymmetry runs one way, and no grant implies execute.
  Encoded once
  ([context/decision-axis-table.md](context/decision-axis-table.md)), and the
  mapping onto each mechanism is pinned by a suite CI runs on x86_64, aarch64 and
  the static-musl target the published binary *is*
  ([context/guide-ci.md](context/guide-ci.md)).
- **What sandbx keeps for itself is out of a grant's reach.** Two paths are the
  harness's: the session transcripts a resumed run replays to the model, and the
  credential file `auth login` writes. The CLI refuses a path grant reaching
  either, in either direction, on every path axis and both run subcommands,
  without asking whether anything is stored there. So `--allow-read ~` and
  `--allow-read /` are refused, with no override flag. The same key reached
  through procfs is closed differently: sandbx clears its own dumpable flag at
  startup, so `/proc/<harness-pid>/environ` is refused even to a reader running as
  you
  ([context/decision-harness-owned-paths.md](context/decision-harness-owned-paths.md)).
  The non-claims below say what each of the two leaves open.
- **The path a grant was vetted as is the path the kernel is told about.** Policy
  is judged in the harness; the helper opens its rules from the path the harness
  already resolved, then refuses the whole run unless each descriptor reads back
  through `/proc/self/fd` as the spelling it was told to open and `fstat`s to the
  `(dev, ino)` the harness vetted. `SandboxPolicy::grant` takes nothing but that
  pair, so an unpinned grant is a compile error rather than a run that would not
  start, and `FsGuard` re-measures the root through an `O_PATH` descriptor at
  every access.

  So a granted directory swapped for another real directory under the same name —
  a `rename(2)`, not a symlink — is refused although it reads back as granted,
  whether the tool that reached it spawns a process or not. A granted name that
  has become a *symlink* is a root to neither layer, though both follow it. Which
  refusal each shape earns, and why a reason drawn from a resolution would leak
  whether an outside path exists, is in
  [context/decision-enforcement-seam.md](context/decision-enforcement-seam.md)
  and
  [context/decision-grant-identity.md](context/decision-grant-identity.md). An
  inode number is reused, which a non-claim below scopes; a symlink *inside* a
  grant is under *Not vulnerabilities*.

## What sandbx does *not* claim

- **Non-Linux is unsupported**, refused at *compile* time: `sandbx-core` does not
  build for a non-Linux target, so no binary that could run a command unsandboxed
  exists.
- **The harness process itself is not sandboxed** — only the commands it runs; a
  vulnerability in sandbx's own code is not contained by sandbx. Nor is the
  helper's supervisor stage: no Landlock ruleset, no seccomp filter, since it must
  spawn the stage that has them. It lives outside the command's PID namespace, and
  touches more than its own argv — with your own privileges: it reads
  `/proc/self/exe` on every run, and under `--allow-dns` the host's
  `/etc/nsswitch.conf` plus whatever `getaddrinfo` touches resolving each
  allowlisted name; it writes the identity maps that make the user namespace
  usable, and renders and binds the files the command then reads as `/etc`. The
  lookups are what the bound `hosts` file is built from, so they precede the bind
  that installs it, and that bind needs the mount namespace the unshare creates —
  which is why these reads land in the unconfined stage rather than the confined
  one.
- **A dependency is not contained.** Anything linked into the binary runs with the
  harness's privileges, not a tool's.
- **The sandbox helper is reached by inode, not by name.** Re-exec goes through
  `/proc/self/exe`, so a replacement renamed over the binary's path cannot
  redirect the next spawn, and `ETXTBSY` blocks in-place overwrite while it runs.
  Two limits: an explicit path to `SandboxedCommand::helper` gets a path, no inode
  behind it; and replacing the binary still reaches the *next* invocation of
  `sandbx`. Nothing refuses a derived default in the directory holding the binary,
  so a no-flag run from a user-level install prefix (`~/.cargo/bin`,
  `~/.local/bin`) grants write there; a `/usr`-rooted prefix is refused.
- **The in-process confirmation is a measurement, not a resolution.** `FsGuard`
  measures a granted root and then performs the access beneath it, so a
  substitution landing between the two — of the root, or of a parent directory a
  walk reopens by path — is granted on the object the confirmation saw. Two swaps,
  both open: a few syscalls wide for the four single-path tools, five guard calls
  between them — `edit` confirms twice, `crate::read_file` then `open_write` once
  the match is known unique. Four of the five confirm then open with `O_NOFOLLOW`;
  the fifth is `ls`, which has no handle form to open and reads the path again. And
  the whole traversal for `find` and `grep`, whose walk confirms its root once and
  then descends — though `grep`'s per-file size test is taken on the handle it is
  about to read rather than on the path a second time, so the measurement and the
  read cannot name different files, and it reaches the trail like any other access
  ([#275](https://github.com/danczw/sandbx/issues/275)).
  Closing either needs the access to run off a directory descriptor, with
  `openat2(dirfd, …, RESOLVE_BENEATH)` for every step below it
  ([#230](https://github.com/danczw/sandbx/issues/230); the `FsGuard` TOCTOU row
  of [context/guide-sandboxing.md](context/guide-sandboxing.md) has the shapes).
  The bare `check_read` and `check_write` bound nothing after the measurement at
  all; no tool uses them. One honest false positive comes with the pin: a
  filesystem with no backing block device takes an anonymous `st_dev`, allocated
  fresh per mount, so a granted tree on a network or autofs mount that remounts
  mid-session starts refusing until the policy is rebuilt.
- **The pin cannot see a reused inode.** An inode number is free once what held it
  is unlinked, and whether it is reused is the filesystem's business, unspecified
  — on ext4, measured, a directory re-created at the same name got the number back
  every time. So a granted directory *deleted and re-created* can compare equal on
  both layers although nothing the harness judged is left. That is the pin's floor
  rather than a gap in how it is checked: a freed number is no evidence the object
  survived, and telling it from the swap above needs a creation time or a
  generation number beside the pair. It takes the same write access to the granted
  root's parent a `rename(2)` substitution does. Figures, and the host they were
  measured on:
  [context/decision-grant-identity.md](context/decision-grant-identity.md).
- **Write access to a project tree is write access to what you run in it next.** A
  granted tree — typed, or derived from the working directory — almost always
  holds files that execute outside the sandbox later, under your own account:
  `.git/hooks/*`, `.git/config`, `.cargo/config.toml`, `Makefile`,
  `package.json` scripts, `rust-toolchain`, and in a build tree or install prefix
  `sandbx` itself. The next ordinary `git commit` or `cargo build` runs what a
  tool rewrote, unconfined. Nothing is refused and nothing can be: it waits on a
  human action. Grant read, keep write to a scratch directory.
- **A pin covers the entry point, not the code the run executes.** `--pin-sha256`
  names the bytes of the one program sandbx `execve`s, closing the swap an
  `--allow-exec` grant allows when the command can also write the tree
  ([#146](https://github.com/danczw/sandbx/issues/146)). After that `execve` a
  pinned program may spawn anything the filesystem policy permits, the whole
  `/usr`, `/bin`, `/lib`, `/lib64` floor the CLI grants by default included — a
  pinned `/usr/bin/python3` being the plain case, the digest fixing the
  interpreter and not the script it is handed.
- **Standing in a system directory is not refused by name.** The derived default
  refuses the trees it grants execute on; `/etc`, `/var`, `/proc` and `/sys` it
  does not — depth is not sensitivity, and a list of dangerous directories has a
  silent first omission. A no-flag run from `/etc` as root derives write over
  `/etc`, which DAC would have allowed anyway. Refused instead is a grant reaching
  a path sandbx itself owns: about sandbx's own state, not a list.
- **The boundary is enforced by convention plus tooling**, not a capability
  system: `unsafe` is forbidden workspace-wide, `sandbx-core` included, and
  spawning a process outside it is a clippy error — but a determined contributor
  can add raw syscalls.
- **Approval is not enforcement, and by default it is per tool per run**
  ([#165](https://github.com/danczw/sandbx/issues/165)). A gate sits between the
  model asking for a tool and `sandbx-tools` running it, and `agent-run` and
  `tui` both answer it from the same flags you typed: the four read-only tools
  run; `write`, `edit` and `bash` come back refused until `--allow-tool` names
  them.

  - **`--approve run`**, the default, asks nothing in between: once a tool is
    approved, every call to it in that turn runs, including one a prompt injection
    induced.
  - **`--approve call`** asks on your terminal before each write and each
    command — `y` for the one call, `n` to refuse it, `a` for every later call to
    that tool — and refuses to start where there is no terminal to ask on. It
    shows the arguments the model chose, cut at 512 characters: the tail of a
    longer command is not shown, and no answer to the prompt reveals it
    ([#169](https://github.com/danczw/sandbx/issues/169)). Under `tui` the flag is
    refused outright, the screen having taken the terminal that question wants
    ([#225](https://github.com/danczw/sandbx/issues/225)).
  - **A terminal that goes away *during* a run is fail-closed and noticed.** The
    read fails rather than returning an answer, so that call and the ones behind
    it are refused, no further request is sent, and the process exits 3 rather
    than 0. A typed end-of-input ends it the same way. What the turn did before is
    on stdout and in `--session`
    ([#218](https://github.com/danczw/sandbx/issues/218)). Under `tui` nothing is
    being asked, but a terminal that hangs up is a turn nobody is watching, so it
    ends the turn and exits 3 on the same reasoning — the screen or the keyboard,
    either one ([#264](https://github.com/danczw/sandbx/issues/264)). A command
    line sandbx would not take exits 64 instead, before a turn or a sandbox
    exists, so none of these codes is reachable by mistyping a flag
    ([#265](https://github.com/danczw/sandbx/issues/265)).

  The gate narrows *which* tools a hijacked turn can use; only the sandbox bounds
  *where* an approved one reaches — with no path flag, read *and write* over the
  directory you ran sandbx from. The request names those roots to the model as
  absolute host paths; a refusal outside them is still indistinguishable from one
  for an absent path
  ([context/decision-approval-gate.md](context/decision-approval-gate.md)).
- **A saved session is a plaintext transcript on your disk.** `--session` writes
  the whole conversation — your prompts, the model's replies, every tool call's
  arguments and every tool's output — as JSON lines under
  `$XDG_STATE_HOME/sandbx/sessions`, else `~/.local/state/sandbx/sessions`.
  Whatever a tool read is in it: a token in a config, a `.env` under
  `--allow-read`, a key a `bash` printed. No encryption, no redaction, no expiry,
  no deletion. A turn stopped on `tui`'s screen writes nothing at all — not the
  prompt and not the part of the answer you read — and an interrupt and a
  hung-up terminal discard it alike, while a tool call already running still
  finished, and what it did is only on the screen you stopped
  ([#271](https://github.com/danczw/sandbx/issues/271)).

  Ownership and integrity are enforced, not secrecy: directory `0700`, transcript
  `0600`, a wider directory narrowed, and a resume refused when another user can
  write or owns the transcript or the directory holding it. One another user can
  merely *read* resumes, with a note on stderr — the disclosure has already
  happened, and a conversation cannot be rotated.

  The store sits outside the working directory on purpose, and a path flag putting
  it back in reach is refused — `--allow-read ~` and `--allow-write` over the
  session root alike, the mode check being blind to a tool in your own run
  ([#173](https://github.com/danczw/sandbx/issues/173);
  [context/decision-on-disk-state.md](context/decision-on-disk-state.md)). Still
  unprotected: a copy, whether you move a transcript into a granted tree or
  another program of yours reads it.
- **Only a spawned command's wall-clock time is bounded.** `bash`'s command is
  killed if it outruns its limit (90 seconds by default), and `sandbox-run` takes
  an opt-in `--timeout`. The other six run in-process, untimed, bounded by *work*
  instead — a cap on files visited and bytes read for `grep` and `find`, the
  single file or directory for the rest
  ([context/decision-bounding-tool-work.md](context/decision-bounding-tool-work.md))
  — on a thread that cannot be cancelled, so one read on a stalled filesystem
  hangs indefinitely. Nothing else is capped: no CPU bound, no memory bound, no
  limit on processes spawned. A fork bomb is unbounded while the call lasts;
  bounded is that it does not outlive it.
- **A running tool call cannot be interrupted.** Only its own deadline stops it;
  no way to cancel one from outside
  ([#26](https://github.com/danczw/sandbx/issues/26)).
- **A bound on the harness's own loop is not a containment claim.** A turn is
  bounded — `TurnLimits::max_rounds` caps the requests one turn may make of the
  model, `TurnLimits::stream_timeout` how long one of them may spend streaming
  ([context/guide-turn-loop.md](context/guide-turn-loop.md)) — but what those
  bound is sandbx's own work, not what a sandboxed command can reach, which is
  what every claim here is about.
- **An unhandled signal aimed at the command itself is ignored.** The command is
  PID 1 of its namespace and the kernel discards a default-disposition signal sent
  to a namespace's init, so `kill -TERM` at the command does nothing unless it
  installed a handler. Kernel-raised faults such as `SIGSEGV` are still delivered,
  and sandbx's own kill is unaffected: it targets the supervisor with `SIGKILL`,
  which an operator killing one by hand should target too.
- **`/proc` inside the sandbox shows host PIDs.** Not remounted for the new
  namespace, since that needs `mount(2)`, which the filter denies. A command reads
  `getpid() == 1` while `/proc/self/stat` reports its host pid, and one building
  `/proc/<getpid()>` by hand reads a different process. A compatibility
  limitation, not a claim about the boundary.
- **A port allowlist is not a destination allowlist.** `--allow-network 443`
  bounds egress to port 443 — on *every* routable host. Landlock's network rules
  match the port only, and seccomp cannot read the address behind `connect`'s
  pointer. Per-host would need a userspace proxy terminating every connection,
  priced and declined — interception is cooperation, not enforcement. And
  `--allow-dns NAME` bounds which *names* resolve, not a destination either: an IP
  literal walks straight past it
  ([#145](https://github.com/danczw/sandbx/issues/145);
  [context/decision-egress-proxy.md](context/decision-egress-proxy.md) prices each
  piece). Blast-radius reduction: it stops a command reaching an SSH port or a
  database, not one exfiltrating over HTTPS.

  **It costs more than it looks.** The claim holds only if everything Landlock
  cannot police is shut, so under a port list seccomp also denies UDP, raw
  sockets, stream sockets on another protocol or in a family that tunnels IP
  inside the kernel, `setsockopt(TCP_ULP)` and TCP Fast Open. So **name
  resolution fails** under `--allow-network <port>`, as do QUIC, HTTP/3, `ping`
  and in-process kTLS. Two ways to resolve anyway — `--allow-dns NAME`, or
  `--dns-over-tcp` with TCP 53 allowlisted and `/etc` readable, which leaves every
  name resolvable — both as recipes in README's *Resolving a name*; why the denial
  is not narrower, in
  [context/decision-port-allowlist.md](context/decision-port-allowlist.md).

  **And it is not uniformly narrower than withholding network.** `bind` is refused
  on every port the list does not name, `bind(0)` included, so a program standing
  up a local listener on an ephemeral port works under the default policy and
  fails here. A port list also puts the command in the *host's* network namespace,
  a port rule inside an empty one having nothing to permit — so host loopback is
  reachable on an allowlisted port, and the host's abstract unix socket namespace
  is no longer isolated by the netns, leaving only the `AF_UNIX` socket denials
  (which `--allow-unix-sockets` lifts) in front of it. Narrower on remote ports,
  wider on what is local.
- **Unix sockets are all-or-nothing.** `--allow-unix-sockets` is one boolean, not
  a chosen path: it grants *every* pathname socket the command can reach — an
  ssh-agent, a docker socket, the session bus. The denial covers both routes to
  an `AF_UNIX` descriptor, `socket` and a connectionless `socketpair`, the latter
  reaching one without calling the former. seccomp cannot follow the pointer
  to `connect`'s path, so the filesystem policy is the only thing that could
  narrow it, and below Landlock ABI V9 (Linux 7.1) it does not: Landlock has no
  traversal right there, so a hardcoded `/run/docker.sock` is dialable holding no
  grant that names it. At V9 the flag confers `ResolveUnix` on the paths it
  granted, and then — and only then — what the command may reach bounds what it
  may dial. Every kernel shipping today is below V9.
- **A variable you pass through is passed in full.** The allowlist is by *name*:
  `--allow-env GH_TOKEN` hands the command the value the harness holds, verbatim.
  No redaction, no partial value, no per-tool scoping, and every process the
  command spawns inherits it — the environment crosses `exec` and nothing narrows
  it again. Sharing a secret without exposing its value has no mechanism — see
  [context/decision-tool-credentials.md](context/decision-tool-credentials.md).
  Exactly one name is refused rather than passed, the next bullet.
- **An agent subcommand refuses to pass the harness's own provider credential to a
  tool.** `--allow-env ANTHROPIC_API_KEY` is refused before the first request goes
  out: sandbx makes the provider call in-process, so no tool call needs that
  value. By the one name sandbx itself reads as a credential, not by a pattern —
  every other variable you name is still passed in full, and `sandbox-run` still
  passes this one, because there the program and its arguments are yours.

  It closes the `--allow-env` route only, narrower than "the environment". A
  stored key is covered by the next bullet; an *exported* one sits in the
  harness's own environment, which a shared procfs would publish to any process
  running as you, so sandbx conceals its own `/proc` entry
  ([#192](https://github.com/danczw/sandbx/issues/192);
  [context/decision-harness-owned-paths.md](context/decision-harness-owned-paths.md)).
  Every *other* same-uid process's `environ` stays reachable through a `/proc`
  grant, as does the audit channel the bullet below names, so "do not grant
  `/proc`" stands. And the flags are the operator's: what this removes is a
  mistake rather than an attacker, a hijacked turn having no `--allow-env` to pass.
- **A stored credential is protected from other users, not from the agent.**
  `sandbx auth login` writes the key to
  `$XDG_CONFIG_HOME/sandbx/credentials.toml`, mode `0600` in a directory at
  `0700`, and refuses to read it when any group or other bit is set on *either* —
  a directory another user may write is one they can substitute a credential in.
  The mode is part of the claim: a too-wide file is refused and named, never
  quietly `chmod`ed back — it was already disclosed, and the fix is to rotate the
  key. `auth logout` is the single exception, removing a key from a too-wide file
  rather than refusing.

  Not encryption: the key is plaintext, readable by your own uid and by root, held
  by the harness, which is not sandboxed. Storing it removes one exposure — a key
  in the file is not in the harness's environment, so no `--allow-env` has it to
  hand over, on either subcommand. A path grant covering it is refused,
  `--allow-read ~/.config` and the file's own path alike
  ([#184](https://github.com/danczw/sandbx/issues/184)). What remains is anything
  reading the file as you outside sandbx — a shell, an editor, a backup. An OS
  keyring would not change that and is not offered
  ([context/decision-credentials.md](context/decision-credentials.md)).
- **The policy itself is visible to the command.** It crosses into the helper as
  argv, and `/proc` inside the sandbox is the host's, so the supervisor's
  `/proc/<pid>/cmdline` is readable from inside and the granted paths and the
  allowlisted variable *names* are readable with it. Not the command's own
  `cmdline`, which the `exec` overwrites with the command. Only names travel that
  way, never values — which is why `--allow-env` takes a name rather than a
  `NAME=VALUE` pair — but a command can enumerate what it was granted. Policy is
  a boundary, not a secret.
- **The capability bounding set is cleared best-effort, not guaranteed.** Dropping
  it needs `CAP_SETPCAP`, which an LSM may strip from a user namespace an
  unprivileged process created: AppArmor's `restrict_unprivileged_userns`
  (default on Ubuntu 24.04+) does, so there the bounding set stays as inherited.
  sandbx records a `degraded` decision on the audit trail at `INFO`, so you need
  not have opted in to see it, and carries on rather than refusing: the bit cannot
  be spent, since with the other four sets empty and `no_new_privs` set the kernel
  will not let an `execve`d binary raise a capability. Do not rely on `CapBnd`
  being empty; do rely on the other four.

  That record crosses back from the helper on a one-way channel the command
  inherits no descriptor onto, carrying mechanism names from a closed set rather
  than from the bytes. Not a boundary the way Landlock is, though: the write end
  lives on the helper's own fd 0 for its lifetime, so a policy granting write over
  `/proc` exposes it as `/proc/<helper-pid>/fd/0` — do not grant one
  ([context/decision-helper-audit-channel.md](context/decision-helper-audit-channel.md)).
- **Denying `memfd_create` does not stop a descriptor being executed.** It is
  blocked because an anonymous in-memory file has no path for Landlock to match
  on, but that closes one route only: a descriptor obtained another way still runs
  via `/proc/self/fd/N` with an ordinary `execve`. What bounds that is Landlock's
  path rules — execute comes only from `allow_read_execute` — not seccomp. A
  pinned run relies on it: Landlock dereferences the magic link, so execing the
  hashed descriptor is checked against the program's real path and needs no
  `/proc` grant.
- **The sandboxed command is not marked non-dumpable.** The kernel resets
  `PR_SET_DUMPABLE=0` to dumpable on every `execve` of an ordinary binary, so
  setting it in the helper would cover the helper only. `RLIMIT_CORE=0` does
  persist across exec, so core dumps are still suppressed; the ptrace-attach
  protection is not achievable here. sandbx's own process *is* non-dumpable — a
  different process, in *What sandbx keeps for itself is out of a grant's reach*
  above — and
  that same reset is why it costs the command nothing: the command's environment
  holds only what `--allow-env` named, plus the constants `imposed_env` sets.

## Known weaknesses

Open, and public on purpose — a sandbox that hides its gaps is worse than one
that names them.

None currently known that let a command reach outside the boundary. Track them
with the [`security` label](https://github.com/danczw/sandbx/labels/security).

## Not vulnerabilities

Documented behaviour; reports of these will be closed as such:

- Network reachable after you passed `--allow-network`, including any host on an
  allowlisted port, name resolution *failing*, `bind` refused on an unlisted port,
  and host loopback reachable — *A port allowlist is not a destination allowlist*.
- A command reading a variable you passed with `--allow-env`, value whole, or one
  of the startup set (`PATH`, `HOME`, `TERM`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TZ`)
  the CLI grants — *A variable you pass through is passed in full*.
- An agent subcommand refusing `--allow-env ANTHROPIC_API_KEY` even when the
  variable is unset, the flag being a statement of intent either way; and
  `sandbox-run` continuing to pass it.
- A path grant refused for reaching the session store or the credential file,
  `--allow-read ~` and `--allow-read /` included, on whichever axis and on a host
  with nothing stored. The verdict comes from the flags, not from what is on disk
  — *What sandbx keeps for itself is out of a grant's reach*.
- No core dump of sandbx itself, and `gdb -p` or `strace -p` against a running
  sandbx being refused. What clearing the harness's own dumpable flag costs.
- A command reading or executing files under a path you granted with
  `--allow-read`, system binaries granted by default included.
- A tool error reporting that a file does not exist, where the path you asked for
  is inside a root you granted — already yours to enumerate with `ls`. Outside
  every granted root, absence and refusal stay indistinguishable.

  A symlink *inside* the grant does not widen that. Resolution follows it, so an
  in-grant name pointing out of the roots is in the grant only by its spelling:
  the six in-process tools refuse it as out of bounds whether its target exists,
  is missing, or sits behind an unreadable directory, so the refusal reports
  nothing about a path you did not grant
  ([#187](https://github.com/danczw/sandbx/issues/187)). A symlink loop is refused
  the same way. `bash` needs no symlink: Landlock has no access right over path
  resolution, so `test -e` answers for any path already.
- A command *reading* a path the CLI granted write on, typed or derived. The CLI
  grants read alongside write either way; the library keeps the axes separate, so
  a write-only drop directory is still expressible through
  `SandboxPolicy::allow_write`.
- A command reading or writing the directory you ran `sandbx` from, when you
  passed no path flag — *It is default-deny*. Under a path flag the command does
  not start there at all: it starts in the first *directory* the policy grants
  write on, else the first it grants read on, and inherits sandbx's own only where
  the policy names no directory at all.
- An agent running a tool call the gate approved, including one a prompt injection
  induced — which, unless `--approve call` is passed, means any call to a tool
  approved for the run. What bounds it is the sandbox, not the asking —
  *Approval is not enforcement*.
- Refusal to run on a kernel older than 6.10, on one with Landlock disabled at
  boot, or where unprivileged user namespaces are disabled — the PID namespace
  that bounds a command's descendants needs one whatever the policy says. And
  failure to *build* for a non-Linux target. All fail-closed, as intended.
- A command surviving its *supervisor* being killed mid-run rather than the call
  ending ([#272](https://github.com/danczw/sandbx/issues/272)). The parent death
  signal is observed armed and undelivered in that case, and the mechanism is
  not yet isolated. Clearing the signal is not the route it once was: the
  command is PID 1 of the PID namespace, `setsid` leaves the process group and
  not the namespace, and the descendant bound comes from the namespace rather
  than from the signal. A survivor is still fully confined — Landlock, seccomp
  and the namespaces are irreversible and inherited — so it is unreaped, not
  unrestricted.
