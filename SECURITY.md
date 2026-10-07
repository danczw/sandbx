# Security Policy

sandbx exists to confine what an AI agent can do, so a weakness in that boundary
is a bug in the product, not in a feature. This document says what the boundary
claims, what is known to be wrong with it, and how to report what it missed.

## Reporting a vulnerability

**Use [private vulnerability reporting](https://github.com/danczw/sandbx/security/advisories/new).**
Please do not open a public issue for a sandbox escape.

Expect a first response within a week. This is a personal project with no
security team and no bug bounty; what you get is an honest assessment, credit if
you want it, and a public advisory once a fix ships. A report of something already
under *Known weaknesses* gets the issue number rather than a new one.

## Supported versions

| version | supported |
|---------|-----------|
| latest pre-release | yes |
| anything older | no |

Pre-1.0 every tag publishes as a pre-release, so "latest pre-release" means the
highest version number on the
[releases page](https://github.com/danczw/sandbx/releases); GitHub's own "latest"
link stays empty until 1.0. There are no backports: fixes land on `main` and ship
in the next tag, and a release is cut per security fix rather than per phase. If
you are running an alpha, run the newest one.

## What sandbx claims to enforce

On Linux 6.10 or newer with unprivileged user namespaces available, for a command
run through `SandboxedCommand`:

| control | mechanism | covers |
|---------|-----------|--------|
| filesystem | Landlock, ABI 5 minimum (`BASELINE_ABI` in `sandbx-core/src/helper/ruleset/compat.rs`), negotiated up to the newest ABI the kernel will enforce *in full* and hard-required at that level | reads, writes, and execution by path, granted separately (`Axis::grants` in `sandbx-core/src/policy.rs` is what each axis confers) |
| entry point | SHA-256 over the descriptor the helper execs, when `--pin-sha256` names a digest (`SandboxedCommand::pin_sha256`) | the bytes of the one program sandbx itself executes, and nothing that program then spawns. The file is opened once after the policy is applied, hashed through that handle, and run as `/proc/self/fd/N`, so no path is re-resolved between the check and the `execve`. A mismatch refuses the run before anything executes, as does an image a pin cannot be checked against: a `#!` script, whose interpreter would re-open the exec'd path, and a program granted execute but not read. See the non-claim below |
| network | an empty network namespace, or — when a port allowlist is given — Landlock TCP port rules plus a seccomp denial of UDP, raw sockets, non-TCP stream protocols, IP-tunnelling families, `TCP_ULP` conversion and TCP Fast Open | IP egress and abstract unix sockets when network is withheld; IP connect and bind narrowed to the allowlisted TCP ports when it is granted per port |
| unix sockets | seccomp-bpf on `socket(AF_UNIX)` | pathname sockets, denied unless granted |
| environment | `env_clear` plus a name allowlist carried on the policy (`SandboxPolicy::allow_env`) | which variables the command inherits from the harness; everything not named is dropped, at every spawn stage, so a secret in the harness's own environment does not cross into the command |
| syscalls | seccomp-bpf | a denylist of dangerous calls: process inspection, namespace and mount manipulation, kernel module loading, the keyring, `io_uring` (which would otherwise run operations without issuing them), handles on other processes (`pidfd_getfd` steals an open descriptor), `userfaultfd`, and `memfd_create`. Namespace creation is denied on every route: `clone` is filtered per `CLONE_NEW*` flag and `clone3` answers `ENOSYS`. A foreign architecture is killed outright rather than refused per call — an i386 binary on x86\_64, or AArch32 on aarch64 — since its syscall numbers mean something else. On x86\_64 the x32 ABI is refused wholesale for the same reason, and needs a rule of its own because it shares the architecture the filter gates on |
| process state | prctl, rlimit, capset | `no_new_privs`, `RLIMIT_CORE=0`, empty effective/permitted/inheritable/ambient capability sets (the bounding set is best-effort — see below) |
| process lifetime | PID namespace + `PR_SET_PDEATHSIG` | every process the command spawned is killed when the call ends, including one that called `setsid` to leave its process group |
| process signalling | PID namespace | a command cannot signal, or even name, any process outside its own namespace |

Three properties matter as much as the list:

- **It fails closed.** A kernel that cannot enforce the baseline is refused, and
  so is a ruleset it only *partly* applies — Landlock leaves an access type
  outside the handled set unrestricted everywhere, so partial application is a
  hole, not a reduced sandbox. `negotiated_abi` walks down from `LATEST_ABI` to
  the ABI 5 floor for the newest ABI the kernel takes in full, and
  `enforcement_verdict` accepts nothing but `RulesetStatus::FullyEnforced`. There
  is no degrading to unrestricted execution.
- **It is default-deny — at the library level, which is the level that is a
  boundary.** A `SandboxPolicy` grants nothing until something is added, and that
  covers the environment too: `SandboxPolicy::default()` passes zero variables.
  Nothing an embedder constructs inherits a default from the CLI.

  The `sandbx` CLI is the convenience layer on top, and opts into three things.
  Two a command needs merely to begin: read on the system binaries and libraries,
  and the handful of environment variables. The third is a real grant — with *no*
  path flag the working directory becomes readable and writable. Any path flag
  replaces that default rather than adding to it, so an explicit policy is never
  widened behind you.

  The derived default refuses to be rooted at the filesystem root, at `$HOME`,
  where home directories live, or anywhere overlapping the system binaries it
  grants execute on; with no usable `HOME` the refusal widens to any direct child
  of those locations rather than lapsing. The README lists them with the flags
  that lift each, and
  `context/decision-default-policy.md` records why the default is shaped this way.
  What that write grant means for files executed *later*, outside the sandbox, is
  a non-claim of its own below.
- **Grants do not widen each other, with one named exception.** Read access does
  not confer the right to execute what it can see, and write access confers
  neither read nor execute — a write-only drop directory stays unreadable, on the
  kernel layer and the in-process layer alike. That is what each *grant* confers:
  the CLI deliberately makes two of them for `--allow-write` (see *Not
  vulnerabilities* below), while the library keeps the axes separate. The
  exception is `allow_read_execute`, named for both rights because it grants both:
  a program needs execute on the binary *and* read on the libraries its loader
  pulls in, so an execute-only grant would start nothing. The asymmetry runs one
  way — execute implies read on the same path, and no grant implies execute.

  This is encoded in one place, `Axis::grants` in `sandbx-core/src/policy.rs`, and
  both enforcement layers derive from it, so neither restates the other's
  semantics. What each still does by hand is map those grants onto its own
  mechanism (Landlock bits, guard roots), and that step is pinned by test.

  Those pinning tests run natively on x86_64 and aarch64, and against the
  static-musl target the published binary *is* — not only the host gnu triple it
  is built on. A static binary loads no interpreter, so what must be granted
  before a command can start differs between the two; enforcement is asserted
  under both at merge time and again before a release is published.

## What sandbx does *not* claim

- **Non-Linux is unsupported**, refused at *compile* time rather than at runtime.
  Landlock, seccomp and the namespaces have no equivalent on another platform, and
  the only fallback would be running the command unsandboxed, so `sandbx-core`
  does not build for a non-Linux target at all. A binary that could run
  unsandboxed cannot be produced.
- **The harness process itself is not sandboxed** — only the commands it runs. A
  vulnerability in sandbx's own code is not contained by sandbx. Nor is the
  helper's supervisor stage: it holds no Landlock ruleset and no seccomp filter,
  because it has to be able to spawn the stage that does. It reads nothing but its
  own arguments, and it lives outside the command's PID namespace, so the command
  has no pid there to name or signal.
- **A dependency is not contained.** Anything linked into the binary runs with
  the harness's privileges, not a tool's.
- **The sandbox helper is reached by inode, not by name.** sandbx re-execs itself
  through `/proc/self/exe`, so a replacement renamed over the binary's path cannot
  redirect the next spawn, and `ETXTBSY` stops it being overwritten in place while
  it runs; a write grant over the directory holding the running `sandbx` therefore
  does not let one tool call choose the confinement of the next. Two limits: a
  library caller passing an explicit path to `SandboxedCommand::helper` gets a
  path, with no inode behind it; and replacing the binary still reaches the *next*
  invocation of `sandbx`, the bullet below. Nothing refuses to derive a default in
  the directory holding the binary, so a no-flag run from a user-level install
  prefix (`~/.cargo/bin`, `~/.local/bin`) grants write there; a `/usr`-rooted
  prefix is still refused, as a path every command may execute.
- **Write access to a project tree is write access to what you run in it next.**
  A granted tree — typed, or derived from the working directory — almost always
  holds files that execute outside the sandbox later, under your own account:
  `.git/hooks/*`, `.git/config`, `.cargo/config.toml`, `Makefile`, `package.json`
  scripts, `rust-toolchain` — and, in a build tree or an install prefix, `sandbx`
  itself. A sandboxed tool may rewrite any of them, and the next ordinary `git
  commit` or `cargo build` runs the result unconfined. Nothing here is refused and
  nothing can be — it waits for a human action, and enumerating the candidates
  would be a denylist whose first omission is silent. If it matters for a tree,
  grant read and keep write to a scratch directory.
- **A pin covers the entry point, not the code the run executes.** `--pin-sha256`
  names the bytes of the one program sandbx `execve`s, closing the swap an
  `--allow-exec` path grant allows when the command can also write the tree
  ([#146](https://github.com/danczw/sandbx/issues/146)). It does not bound what
  runs after that `execve`: a pinned program may spawn anything the filesystem
  policy permits, including every binary under the `/usr`, `/bin`, `/lib` and
  `/lib64` floor the CLI grants by default — thousands of them, not an operator's
  choice — with nothing of sandbx's in those `execve` calls to check. A pinned
  interpreter is the plain case: the digest fixes which `/usr/bin/python3` runs and
  says nothing about the script it is handed. There is no warning mode; the bypass
  is omitting the digest.
- **Standing in a system directory is not refused by name.** The derived default
  refuses the trees it grants execute on, but `/etc`, `/var`, `/proc` and `/sys`
  are not: depth is not sensitivity, and a guard holding a list of dangerous
  directories has a silent first omission. A no-flag run from `/etc` as root
  derives write over `/etc` — which DAC would have allowed that command anyway,
  and which the path flags state out loud.
- **The boundary is enforced by convention plus tooling**, not by a capability
  system: `unsafe` is forbidden workspace-wide, `sandbx-core` included, and
  spawning a process outside it is a clippy error — but a determined contributor
  can add raw syscalls.
- **Approval is not enforcement, and it is per tool per run**
  ([#165](https://github.com/danczw/sandbx/issues/165)). A gate sits between the
  model asking for a tool and `sandbx-tools` running it, and `agent-run` answers
  it from the flags you typed: the four read-only tools run, and a `write`, an
  `edit` or a `bash` comes back refused until `--allow-tool` names it. Nothing
  asks you in between, so once a tool is approved every call to it in that turn
  runs, including one a prompt injection induced. The gate narrows *which* tools a
  hijacked turn can use; the sandbox is the only thing bounding *where* an approved
  one reaches, so the policy `agent-run` derives is the whole of what an approved
  call can touch — with no path flag, read *and write* over the directory you ran
  it from. sandbx bounds what a tool call can reach; it does not decide whether it
  should run. The request `agent-run` sends names those roots to the model as
  absolute host paths, so it does not probe for them; a refusal outside them is
  still indistinguishable from one for a path that is simply absent.
- **A saved session is a plaintext transcript on your disk.** `agent-run
  --session` writes the whole conversation — your prompts, the model's replies,
  every tool call's arguments and every tool's output — as JSON lines under
  `$XDG_STATE_HOME/sandbx/sessions`, or `~/.local/state/sandbx/sessions`.
  Whatever a tool read into the conversation is in that file: a config holding a
  token, a `.env` inside an `--allow-read` tree, a `bash` output that printed a
  key. There is no encryption, no redaction and no expiry; nothing deletes a
  transcript, and it grows for as long as you resume it.

  What is enforced is ownership and integrity, not secrecy. sandbx creates the
  directory `0700` and each transcript `0600`, narrows a directory it finds wider,
  and refuses to resume a transcript — or a directory holding one — that another
  user can write or that another user owns, because a history somebody else chose
  is replayed to a model that calls tools. One another user can merely *read*
  resumes and says so on stderr: the disclosure has already happened by the time
  the mode is read, and unlike a credential a conversation cannot be rotated.

  The store sits outside the working directory on purpose, so a no-flag run does
  not grant a tool write over its own history. A path flag can put it back in
  reach, and that is not refused: `--allow-read ~` hands the model every
  transcript you have, and `--allow-write` over the session root lets one turn
  choose what the next is told it said. The mode check cannot see that one — a
  tool in your own run writes with your own uid and leaves the mode at `0600` —
  so the defence has to be a policy that refuses the grant
  ([#173](https://github.com/danczw/sandbx/issues/173)). Until it lands, keep path
  grants off your home directory and off the session root.
- **Only a spawned command's wall-clock time is bounded.** `bash`'s command is
  killed if it outruns its limit (90 seconds by default), and `sandbox-run` takes
  an opt-in `--timeout`; those calls always return by then. The other six tools
  run in-process and are not timed at all. `grep` and `find` are bounded by *work*
  instead — a cap on the files a walk visits and the bytes a search reads, after
  which the result says it stopped early — and `read`, `write`, `edit` and `ls` by
  the single file or directory they touch. None of that is a time bound: tools run
  on a blocking thread that cannot be cancelled, so one read on a stalled
  filesystem can hang indefinitely. Nothing else is capped — no CPU bound, no
  memory bound, no limit on processes spawned. A fork bomb is unbounded while the
  call lasts; what is bounded is that it does not outlive it.
- **A running tool call cannot be interrupted.** Only its own deadline stops it;
  there is no way to cancel one from outside
  ([#26](https://github.com/danczw/sandbx/issues/26)).
- **An unhandled signal aimed at the command itself is ignored.** The command is
  PID 1 of its namespace, and the kernel discards a default-disposition signal
  sent to a namespace's init, so `kill -TERM` at the command does nothing unless
  it installed a handler. Kernel-raised faults such as `SIGSEGV` are still
  delivered, and sandbx's own kill is unaffected because it targets the supervisor
  with `SIGKILL` — which is what an operator killing one by hand should target too.
- **`/proc` inside the sandbox shows host PIDs.** It is not remounted for the new
  namespace — that would need `mount(2)`, which the filter denies — so a command
  reads `getpid() == 1` while `/proc/self/stat` reports its host pid, and one that
  builds `/proc/<getpid()>` by hand reads a different process. A compatibility
  limitation, not a claim about the boundary.
- **A port allowlist is not a destination allowlist.** `--allow-network 443`
  bounds egress to port 443 — on *every* routable host. Landlock's network rules
  match the port and nothing else, and seccomp cannot read the `sockaddr` behind
  `connect`'s pointer, so neither can see where a connection is going. Per-host
  would mean terminating every connection in a userspace proxy, and that proxy has
  been priced and declined rather than merely postponed: its interception is
  cooperation, not enforcement, since `HTTP_PROXY` binds only programs that read it
  and an `LD_PRELOAD` shim on `connect` is stepped around by a static binary —
  which sandbx's own release artifacts are. One piece of it is claimable, a
  resolver bounding which *names* resolve, and that is not a destination control
  either ([#145](https://github.com/danczw/sandbx/issues/145);
  [context/decision-egress-proxy.md](context/decision-egress-proxy.md) prices each
  piece). Treat the flag as a reduction in blast radius, not a destination control:
  it stops a command reaching an SSH port or a database, not one exfiltrating over
  HTTPS.

  It also costs more than it looks. The claim holds only if everything Landlock
  cannot police is shut, so while a port list is in force seccomp denies UDP, raw
  sockets, stream sockets on another protocol (MPTCP, SCTP), stream sockets in a
  family that tunnels IP from inside the kernel (AF_SMC, AF_TIPC), the
  `setsockopt(TCP_ULP)` conversion into one, and TCP Fast Open, which connects
  inside a `sendmsg` and never passes the hook the port rules hang off. So **name
  resolution fails** under `--allow-network <port>` — `getaddrinfo` can reach
  neither a UDP resolver nor `AF_NETLINK` — and so do QUIC, HTTP/3, `ping` and
  in-process kTLS. A name can still be resolved over TCP, with `--dns-over-tcp`
  and TCP 53 allowlisted; the README's *Resolving a name* has the recipe and its
  limits, and `context/decision-port-allowlist.md` why the denial is not narrower.

  **And it is not uniformly narrower than withholding network.** `bind` is refused
  on every port the list does not name, `bind(0)` included, so a program that
  stands up a local listener on an ephemeral port works under the default policy
  and fails under `--allow-network <port>`. A port allowlist also puts the command
  in the *host's* network namespace, since a port rule inside an empty one would
  have nothing to permit — so host loopback services are reachable on an
  allowlisted port, and the host's abstract unix socket namespace is no longer
  isolated by the netns, leaving only the `socket(AF_UNIX)` denial (which
  `--allow-unix-sockets` lifts) in front of it. Narrower on which remote ports are
  reachable, wider on what is local.
- **Unix sockets are all-or-nothing.** `--allow-unix-sockets` grants *every*
  pathname socket the filesystem policy can reach — an ssh-agent, a docker
  socket, the session bus — not a chosen one. seccomp compares register values and
  the path passed to `connect` is behind a pointer it cannot follow; Landlock
  gained a path-scoped right only in ABI V9 (Linux 7.1), which is not available in
  practice. What the command can *read* bounds which sockets exist to be dialled,
  so keep the filesystem policy narrow when granting this.
- **A variable you pass through is passed in full.** The allowlist is by *name*:
  `--allow-env GH_TOKEN` hands the command the value the harness holds, verbatim.
  No redaction, no partial value, no per-tool scoping, and every process the
  command spawns inherits it — the environment crosses `exec` and nothing
  downstream narrows it again. So the allowlist decides *whether* a secret is
  shared, never *how much* of it, and naming a credential is the whole of handing
  one over. Doing that without exposing the value has no mechanism — see
  [context/decision-tool-credentials.md](context/decision-tool-credentials.md) for
  why none of the shapes that would is claimable today. Name a variable only when
  the command genuinely needs its value. Exactly one name is refused rather than
  passed, and it is the next bullet.
- **`agent-run` refuses to pass the harness's own provider credential to a tool.**
  `--allow-env ANTHROPIC_API_KEY` is refused before the first request goes out:
  sandbx makes the provider call in-process, so no tool call needs that value, and
  naming it would hand the key that pays for the model to a process whose
  arguments the model chose. The refusal is by the one name sandbx itself reads as
  a credential, not by a pattern — every other variable you name is still passed
  in full, and `sandbox-run` still passes this one, because there the program and
  its arguments are yours and the command may *be* the thing calling the provider.
  It closes the `--allow-env` route only, and that is narrower than "the
  environment". A key stored by `sandbx auth login` is still reachable through a
  read grant covering your config directory, which is the next bullet; a key you
  *exported* is still in the harness's own environment, and the harness is not
  sandboxed against a procfs it shares, so a grant reaching `/proc` reaches
  `/proc/<harness-pid>/environ` and the key in it
  ([#192](https://github.com/danczw/sandbx/issues/192)). That is the hazard the
  audit socket bullet names below, arriving by the same route: do not grant
  `/proc`.
  And the flags are the operator's, so what this removes is a
  mistake rather than an attacker — a hijacked turn cannot pass `--allow-env`.
- **A stored credential is protected from other users, not from the agent.**
  `sandbx auth login` writes the key to
  `$XDG_CONFIG_HOME/sandbx/credentials.toml` with mode `0600` in a directory at
  `0700`, and refuses to read the file when any group or other bit is set on
  *either* — a directory another user may write is one they can rename the
  credential out of and substitute their own. The mode is part of the claim, so a
  too-wide file is refused and named, never quietly `chmod`ed back: it was already
  disclosed, and the fix is to rotate the key. `auth logout` is the single
  exception, removing a key from a too-wide file rather than refusing — the
  alternative leaves an exposed credential on disk to protect it from exposure.

  That bounds who *else* on the host can read it. It is not encryption: the key is
  plaintext, readable by your own uid and by root, and the process holding it is
  the harness, which is not sandboxed. Storing it removes one exposure — a key in
  the file is not in the harness's environment, so no `--allow-env` has it to hand
  over, on either subcommand — and adds the one to plan around:
  the file lives under your config directory, so a filesystem grant covering it
  (`--allow-read ~/.config`) reads the credential into the agent's reach
  ([#184](https://github.com/danczw/sandbx/issues/184)). The
  working-directory default refuses `$HOME` and the directories holding it, so
  reaching the file takes an explicit flag; it takes only one. An OS keyring would
  not change this and is not offered — see
  [context/decision-credentials.md](context/decision-credentials.md).
- **The policy itself is visible to the command.** It crosses into the helper as
  argv, and a process can read its own `/proc/self/cmdline`, so the granted paths
  and the allowlisted variable *names* are readable from inside the sandbox. Only
  names travel that way and never values — which is why `--allow-env` takes a name
  rather than a `NAME=VALUE` pair — but a command can enumerate what it was
  granted. Policy is a boundary, not a secret.
- **The capability bounding set is cleared best-effort, not guaranteed.** Dropping
  it needs `CAP_SETPCAP`, which an unprivileged process holds only inside a user
  namespace it created itself — and not even there when an LSM strips capabilities
  from such a namespace. AppArmor's `restrict_unprivileged_userns` (default on
  Ubuntu 24.04+) does that, so on those hosts the bounding set is left as
  inherited. sandbx records it on the audit trail as a `degraded` decision — at
  `INFO`, so you need not have opted in to see it — and carries on rather than
  refusing, because the bit cannot be spent: with the other four sets empty and
  `no_new_privs` set, the kernel will not let an `execve`d binary raise a
  capability. Do not rely on `CapBnd` being empty; do rely on the other four.

  The drop is attempted in the helper, which installs no log subscriber, so the
  record crosses back on a dedicated one-way channel and is emitted by sandbx. The
  command inherits no descriptor onto that channel, and a record's mechanism name
  comes from a closed set rather than from the bytes, so a command cannot invent
  one. It is not a boundary the way Landlock is, though: the write end lives on the
  helper's own fd 0 for the helper's lifetime, so a policy granting write access
  over `/proc` would expose it as `/proc/<helper-pid>/fd/0`. Do not grant one.
- **Denying `memfd_create` does not stop a descriptor being executed.** The
  syscall is blocked because an anonymous in-memory file has no path for Landlock
  to match on, but that denies one route rather than guaranteeing anything about
  descriptors in general: one obtained another way can still be run via
  `/proc/self/fd/N` with an ordinary `execve`. What bounds that is Landlock's path
  rules — execute comes only from `allow_read_execute` — not seccomp. A pinned run
  relies on exactly that: Landlock dereferences the magic link, so execing the
  hashed descriptor is still checked against the program's real path and needs no
  grant on `/proc`.
- **The sandboxed command is not marked non-dumpable.** The kernel resets
  `PR_SET_DUMPABLE=0` to dumpable on every `execve` of an ordinary binary, so
  setting it in the helper would affect only the helper's own process, not the
  command it re-execs into. Core dumps are still fully suppressed via
  `RLIMIT_CORE=0`, which does persist across exec; the ptrace-attach protection
  `PR_SET_DUMPABLE=0` would otherwise add is not achievable here.

## Known weaknesses

Open, and public on purpose — a sandbox that hides its gaps is worse than one
that names them.

None currently known that let a command reach outside the boundary. Track them
with the [`security` label](https://github.com/danczw/sandbx/labels/security).

## Not vulnerabilities

These are documented behaviour, and reports of them will be closed as such:

- Network reachable after you passed `--allow-network`, including any host on an
  allowlisted port after `--allow-network <port>` — see *A port allowlist is not a
  destination allowlist* above — and including name resolution *failing*, `bind`
  being refused on an unlisted port, and host loopback being reachable under that
  form. A host you did not name, reached on a port you did, is what the flag says
  it does.
- A command reading an environment variable you passed with `--allow-env`,
  including the startup set (`PATH`, `HOME`, `TERM`, `LANG`, `LC_ALL`, `LC_CTYPE`,
  `TZ`) the CLI grants so that a program named without a leading `/` is looked up
  in your `PATH` rather than only in the C library's fallback. The value arrives
  whole — see *A variable you pass through is passed in full* above.
- `agent-run` refusing `--allow-env ANTHROPIC_API_KEY`, including when the
  variable is unset, since the flag is a statement of intent either way. And
  `sandbox-run` continuing to pass it, since there the program and its arguments
  are yours — see *`agent-run` refuses to pass the harness's own provider
  credential to a tool* above.
- A command reading or executing files under a path you granted with
  `--allow-read`, including system binaries granted by default so that commands
  can start at all.
- A tool error reporting that a file does not exist, where the path you asked
  for is inside a root you granted. That area is already yours to enumerate with
  `ls`, and the agent has to tell a wrong filename from a refused one. Outside
  every granted root, absence and refusal stay indistinguishable.

  A symlink *inside* the grant is the edge of that claim: resolution follows it,
  so an in-grant name pointing out of the roots reports whether its target
  exists — "could not find" where it does not, the uniform refusal where it
  does. The probe is one bit about a path you did not grant, and planting the
  symlink needs write access the six in-process tools do not have. `bash` has it
  and needs no symlink: Landlock has no access right over path resolution, so
  `test -e` answers for any path already.
- A command *reading* a path the CLI granted write on — whether you typed
  `--allow-write` or the working-directory default derived it. The CLI grants read
  alongside write either way, because a tool that can rewrite a tree but not read
  it back is a trap rather than a safeguard. The library keeps the two axes
  separate, so a genuinely write-only drop directory is still expressible through
  `SandboxPolicy::allow_write`.
- A command reading or writing the directory you ran `sandbx` from, when you
  passed no path flag. That is the documented default — see *It is default-deny*
  above for what it covers and what it refuses.
- An agent running a tool call the gate approved — which, as things stand, means
  any call to a tool approved for the run rather than that one call (see *Approval
  is not enforcement* above). That includes a call a prompt injection induced, and
  one reached through `agent-run`, which is a real path and not a library-only
  one. What bounds it is the sandbox, not the asking.
- Refusal to run on a kernel older than 6.10, or on one with Landlock disabled at
  boot. That is fail-closed behaviour working as intended.
- Failure to *build* for a non-Linux target. Also intended — see above.
- Refusal to run where unprivileged user namespaces are disabled. The PID
  namespace that bounds a command's descendants needs one, whatever the policy
  says, so this is the same fail-closed behaviour rather than a lost feature.
- A descendant surviving the call because the command both had its parent death
  signal cleared by a secure `exec` *and* called `setsid` to leave the process
  group. Both would have to happen together, and a survivor is still fully
  confined — Landlock, seccomp and the namespaces are irreversible and inherited —
  so it is unreaped, not unrestricted.
