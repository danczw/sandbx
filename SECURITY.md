# Security Policy

sandbx's entire purpose is to confine what an AI agent can do. A weakness in that
boundary is not a bug in a feature — it is a bug in the product. This document
says what the boundary currently claims, what is known to be wrong with it, and
how to tell us about something we missed.

## Reporting a vulnerability

**Use [private vulnerability reporting](https://github.com/danczw/sandbx/security/advisories/new).**
Please do not open a public issue for a sandbox escape.

You should get a first response within a week. This is a personal project with
no security team and no bug bounty; what you will get is an honest assessment,
credit if you want it, and a public advisory once a fix ships.

If a report turns out to describe something already listed under *Known
weaknesses*, we will say so and point you at the issue rather than treat it as
new.

## Supported versions

| version | supported |
|---------|-----------|
| latest pre-release | yes |
| anything older | no |

Pre-1.0, every tag that publishes publishes as a pre-release, suffixed or not, so
"latest pre-release" means the highest version number on the
[releases page](https://github.com/danczw/sandbx/releases) — GitHub's own
"latest" link stays empty until 1.0. There are no backports: fixes land on `main`
and ship in the next tagged pre-release. If you are running an alpha, run the
newest one.

The intended release rhythm was one per completed phase. In practice it has become
one per security fix — alpha.4 and alpha.5 were both cut for a sandbox weakness
rather than a feature. That is the cadence to expect while pre-1.0: a fix to the
boundary ships on its own rather than waiting for whatever else is in flight.

## What sandbx claims to enforce

On Linux 6.10 or newer with unprivileged user namespaces available, for a command
run through `SandboxedCommand`:

| control | mechanism | covers |
|---------|-----------|--------|
| filesystem | Landlock, ABI 5 minimum (`BASELINE_ABI` in `sandbx-core/src/helper/ruleset/compat.rs`), negotiated up to the newest ABI the kernel will enforce *in full* and hard-required at that level | reads, writes, and execution by path, granted separately (`Axis::grants` in `sandbx-core/src/policy.rs` is what each axis confers) |
| network | an empty network namespace, or — when a port allowlist is given — Landlock TCP port rules plus a seccomp denial of UDP, raw sockets and non-TCP stream protocols | IP egress and abstract unix sockets when network is withheld; IP egress narrowed to the allowlisted TCP ports when it is granted per port |
| unix sockets | seccomp-bpf on `socket(AF_UNIX)` | pathname sockets, denied unless granted |
| environment | `env_clear` plus a name allowlist carried on the policy (`SandboxPolicy::allow_env`) | which variables the command inherits from the harness; everything not named is dropped, at every spawn stage, so a secret in the harness's own environment does not cross into the command |
| syscalls | seccomp-bpf | a denylist of dangerous calls: process inspection, namespace and mount manipulation, kernel module loading, the keyring, `io_uring` (which would otherwise run operations without issuing them), handles on other processes (`pidfd_getfd` steals an open descriptor), `userfaultfd`, and `memfd_create`. Namespace creation is denied on every route, not just `unshare`: `clone` is filtered per `CLONE_NEW*` flag and `clone3` answers `ENOSYS`. A foreign architecture is killed outright rather than refused per call — an i386 binary on x86\_64, or AArch32 on aarch64 — since its syscall numbers mean something else. On x86\_64 the x32 ABI is refused wholesale for the same reason, and needs a rule of its own because, unlike those, it shares the architecture the filter gates on |
| process state | prctl, rlimit, capset | `no_new_privs`, `RLIMIT_CORE=0`, empty effective/permitted/inheritable/ambient capability sets (the bounding set is best-effort — see below) |
| process lifetime | PID namespace + `PR_SET_PDEATHSIG` | every process the command spawned is killed when the call ends, including one that called `setsid` to leave its process group |
| process signalling | PID namespace | a command cannot signal, or even name, any process outside its own namespace |

Three properties matter as much as the list:

- **It fails closed.** A kernel that cannot enforce the baseline is refused. A
  ruleset the kernel only partly applies is treated as failure. sandbx does not
  degrade to unrestricted execution and then carry on.

  Both halves are load-bearing, and the second one took until #52 to become
  true. Landlock leaves any access type *not* in the handled set unrestricted
  everywhere, so a partly applied ruleset is a hole, not a reduced sandbox.
  sandbx therefore asks the kernel for one ABI — the newest it will accept in
  full, found by `negotiated_abi` walking down from `LATEST_ABI` to the ABI 5
  floor — and `enforcement_verdict` then accepts nothing but
  `RulesetStatus::FullyEnforced`. The earlier design asked for the newest ABI
  *best-effort* and refused only a ruleset enforced not at all, which meant
  every kernel older than that ABI ran `PartiallyEnforced` and was accepted.
- **It is default-deny.** A policy grants nothing until something is added, and
  that covers the environment too: `SandboxPolicy::default()` passes zero
  variables. The `sandbx` CLI opts into the handful a command needs in order to
  start, the same way it opts into the system binaries (see the flag table in the
  README). Until #98 this was the one thing the sandbox did not bound at all —
  not a policy that defaulted open, but an axis that did not exist — so a command
  inherited the harness's entire environment.
- **Grants do not widen each other, with one named exception.** Read access
  does not confer the right to execute what it can see, and write access confers
  neither read nor execute — a write-only drop directory stays unreadable, on
  the kernel layer and the in-process layer alike. This describes what each
  *grant* confers: the `sandbx` CLI deliberately makes two of them for
  `--allow-write` (see *Not vulnerabilities* below), while the library keeps the
  axes separate. The exception is
  `allow_read_execute`, named for both rights because it grants both: a program
  needs execute on the binary *and* read on the libraries its loader pulls in,
  so an execute-only grant would start nothing. That asymmetry runs one way:
  execute implies read on the same path, and no grant implies execute.

  This paragraph is encoded in one place: `Axis::grants` in
  `sandbx-core/src/policy.rs`. Both enforcement layers derive from it — the
  kernel layer's Landlock rights and the in-process guard's roots — so neither
  restates the other's semantics the way they did in #49 and #50. What each layer
  still does by hand is map those grants onto its own mechanism (Landlock bits,
  guard roots); that step is pinned by test, not by construction. The helper argv
  and the audit record derive their per-axis loops from the same table, but their
  flag spellings and record fields are necessarily hand-written.

  Those pinning tests run natively on both published architectures, x86_64 and
  aarch64, and against the static-musl target the published binary *is* — not
  only the host gnu triple it is built on. A static binary loads no interpreter,
  so what a command needs granted before it can start differs between the two,
  and enforcement is asserted under both at merge time and again before a
  release is published.

## What sandbx does *not* claim

- **Non-Linux is unsupported**, and refused at *compile* time rather than at
  runtime. Landlock, seccomp and the namespaces have no equivalent on another
  platform, so there is nothing to fall back to except running the command
  unsandboxed — `sandbx-core` therefore does not build for a non-Linux target at
  all. A binary that could run unsandboxed cannot be produced, which is a stronger
  guarantee than an error returned at startup.
- **The harness process itself is not sandboxed** — only the commands it runs.
  A vulnerability in sandbx's own code is not contained by sandbx. The same is
  true of the helper's supervisor stage: it holds no Landlock ruleset and no
  seccomp filter, because it has to be able to spawn the stage that does. It
  reads nothing but its own arguments, and a command cannot reach it — the
  supervisor lives outside the PID namespace the command runs in, so it has no
  pid there to be named or signalled.
- **A dependency is not contained.** Anything linked into the binary runs with
  the harness's privileges, not a tool's.
- **A write grant over sandbx's own binary defeats the boundary.** The sandbox
  helper is this binary re-executed, resolved through `current_exe()`, so a
  policy granting write over the directory holding the installed `sandbx` is a
  grant to replace the thing that does the enforcing — and the replacement runs
  unsandboxed on the next spawn. No default grant confers write, so this takes an
  explicit `--allow-write`. It is worth stating because `agent-run` is where the
  grant stops being something only the operator acts on: the model chooses the
  paths it writes to, within what was granted, and a prompt injection chooses
  with it.
- **The boundary is enforced by convention plus tooling**, not by a capability
  system: `unsafe` is forbidden workspace-wide, `sandbx-core` included, and
  spawning a process outside it is a clippy error — but a determined contributor
  can add raw syscalls.
- **Approval is not enforcement, and there is no approval step yet.** The agent
  loop runs every tool call the model asks for — nothing sits between the model
  requesting one and `sandbx-tools` executing it. `sandbx agent-run` reaches that
  loop, so this is what a prompt you type does, not only what the library would do:
  the sandbox is the only thing between a prompt-injected tool call and your files,
  which is why it is default-deny and why the grants you pass `agent-run` are the
  whole of what a hijacked turn can touch. A gate will not change this bullet: a
  tool call you approve runs. sandbx bounds what it can reach; it does not decide
  whether it should run.
- **Only a spawned command's wall-clock time is bounded.** `bash`'s command is
  killed if it outruns its limit (90 seconds by default), and `sandbox-run` takes
  an opt-in `--timeout`; that call always returns by then. The other six tools run
  in-process and are not timed at all. `grep` and `find` are bounded by *work*
  instead — a cap on the files a walk visits and on the bytes a search reads,
  after which the result says it stopped early — and `read`, `write`, `edit` and
  `ls` are bounded only by the single file or directory they touch. None of that
  is a time bound: one read on a stalled filesystem can hang indefinitely, and no
  deadline anywhere cuts it short, because tools run on a blocking thread that
  cannot be cancelled. Nothing else is capped either: no CPU bound, no memory
  bound, and no limit on how many processes a command spawns. The sandbox governs
  *what* a command can reach, and *how long* a spawned one may run, but not *how
  much* it can consume. A fork bomb is still unbounded while the call lasts; what
  is bounded is that it does not outlive it.
- **An unhandled signal aimed at the command itself is ignored.** The command is
  PID 1 of its namespace, and the kernel discards a default-disposition signal
  sent to a namespace's init — so `kill -TERM` at the command from inside or
  outside does nothing unless the command installed a handler. Faults the kernel
  raises itself, such as `SIGSEGV`, are still delivered, and sandbx's own kill is
  unaffected because it targets the supervisor with `SIGKILL`. An operator killing
  a sandboxed command by hand should target the supervisor, not the command.
- **`/proc` inside the sandbox shows host PIDs.** It is not remounted for the new
  namespace — that would need `mount(2)`, which the filter denies — so a command
  reads `getpid() == 1` while `/proc/self/stat` reports its host pid. A program
  that builds `/proc/<getpid()>` by hand therefore reads a different process.
  A compatibility limitation, not a claim about the boundary.
- **A running tool call cannot be interrupted.** Only its own deadline stops it;
  there is no way to cancel one from outside
  ([#26](https://github.com/danczw/sandbx/issues/26)).
- **A port allowlist is not a destination allowlist.** `--allow-network 443`
  bounds egress to port 443 — on *every* routable host. Landlock's network rules
  match the port and nothing else, and seccomp cannot read the `sockaddr` behind
  `connect`'s pointer, so neither mechanism can see where a connection is going.
  Per-host would mean terminating every connection in a userspace proxy, which
  sandbx does not have
  ([#145](https://github.com/danczw/sandbx/issues/145)). Treat the flag as a
  reduction in blast radius, not as a destination control: it stops a command
  reaching an SSH port or a database, not a command exfiltrating over HTTPS.

  It also costs more than it looks. A port list claims egress reaches the ports
  it names and nowhere else, which is only true if the transports Landlock
  cannot police are shut: UDP, raw sockets, and stream sockets carrying a
  protocol other than TCP (MPTCP, SCTP), all denied by seccomp while a port list
  is in force. So **name resolution fails** under `--allow-network <port>` —
  `getaddrinfo` can reach neither a UDP resolver nor `AF_NETLINK` — and so do
  QUIC, HTTP/3 and `ping`. Until that is addressed
  ([#147](https://github.com/danczw/sandbx/issues/147)), a command needing names
  wants a bare `--allow-network`, or an address resolved before the run.
  `context/decision-port-allowlist.md` records why the denial is not narrower.
- **Unix sockets are all-or-nothing.** `--allow-unix-sockets` grants *every*
  pathname socket the filesystem policy can reach — an ssh-agent, a docker
  socket, the session bus — not a chosen one. seccomp compares register values
  and the path passed to `connect` is behind a pointer it cannot follow;
  Landlock gained a path-scoped right only in ABI V9 (Linux 7.1), which is not
  available in practice yet. Until then, what the command can *read* is what
  bounds which sockets exist to be dialled, so keep the filesystem policy narrow
  when granting this.
- **A variable you pass through is passed in full.** The environment allowlist is
  by *name*: `--allow-env ANTHROPIC_API_KEY` hands the command the value the
  harness holds, verbatim. There is no redaction, no partial value, no per-tool
  scoping, and every process the command spawns inherits it — the environment
  crosses `exec` and nothing downstream narrows it again. So the allowlist decides
  *whether* a secret is shared, never *how much* of it. Handing a credential to a
  tool without exposing the value to the tool is a separate problem
  ([#41](https://github.com/danczw/sandbx/issues/41)) and is not solved here;
  until it is, name a variable only when the command genuinely needs its value.
  The example is not hypothetical: `agent-run` reads `ANTHROPIC_API_KEY` from the
  harness's own environment, so the harness holds a live key for the whole turn.
  A tool the agent runs does not see it — the environment is cleared and only
  what the policy names crosses — unless you name that variable, which hands the
  key to a process a hijacked turn chose the arguments for.
- **The policy itself is visible to the command.** It crosses into the helper as
  argv, and a process can read its own `/proc/self/cmdline`, so the granted paths
  and the allowlisted variable *names* are readable from inside the sandbox. Only
  names travel that way and never values — which is why `--allow-env` takes a name
  rather than a `NAME=VALUE` pair — but a command can enumerate what it was
  granted. Policy is a boundary, not a secret.
- **The capability bounding set is cleared best-effort, not guaranteed.**
  Dropping it needs `CAP_SETPCAP`, which an unprivileged process holds only
  inside a user namespace it created itself — and not even there when an LSM
  strips capabilities from such a namespace. AppArmor's
  `restrict_unprivileged_userns` (default on Ubuntu 24.04+) does that, so on
  those hosts the bounding set is left as inherited. sandbx records it on the
  audit trail as a `degraded` decision — at `INFO`, so it is not something you
  have to have opted into seeing — and carries on rather than refusing, because
  the bit cannot be spent: with the other four sets empty and `no_new_privs` set,
  the kernel will not let an `execve`d binary raise a capability, so a leftover
  bounding bit never becomes privilege. Do not rely on `CapBnd` being empty; do
  rely on the other four.

  That record takes a detour worth knowing about. The drop is attempted in the
  sandbox helper, which runs as its own process and installs no log subscriber, so
  the record crosses back to sandbx on a dedicated one-way channel and is emitted
  there. The command inherits no descriptor onto that channel, and the mechanism
  name on a record is drawn from a closed set rather than from the bytes, so a
  command cannot invent a mechanism. The channel is not a boundary the way Landlock
  is, though: the write end lives on the helper's own fd 0 for the helper's
  lifetime, so a policy granting write access over `/proc` would expose it as
  `/proc/<helper-pid>/fd/0`. Do not grant one.
- **Denying `memfd_create` does not stop a descriptor being executed.** The
  syscall is blocked because an anonymous in-memory file has no path for Landlock
  to match on, but that is a denial of one route, not a guarantee about file
  descriptors in general: a descriptor obtained some other way can still be run
  via `/proc/self/fd/N` with an ordinary `execve`. What bounds that is Landlock's
  path rules — execute comes only from `allow_read_execute` — not seccomp.
- **The sandboxed command is not marked non-dumpable.** `PR_SET_DUMPABLE=0`
  was investigated for #39 and found ineffective for this design: the kernel
  resets that flag to dumpable on every `execve` of an ordinary binary, so
  setting it in the helper only affects the helper's own process, not the
  command it re-execs into. Core dumps are still fully suppressed via
  `RLIMIT_CORE=0`, which does persist across exec; the ptrace-attach
  protection `PR_SET_DUMPABLE=0` would otherwise add is not achievable here.

## Known weaknesses

Open, and public on purpose — a sandbox that hides its gaps is worse than one
that names them.

None currently known that let a command reach outside the boundary.

Track them with the [`security` label](https://github.com/danczw/sandbx/labels/security).

## Not vulnerabilities

These are documented behaviour, and reports of them will be closed as such:

- Network reachable after you passed `--allow-network`, including any host on an
  allowlisted port after `--allow-network <port>` — see *A port allowlist is not
  a destination allowlist* above — and including name resolution *failing* under
  that form.
- A command reading an environment variable you passed with `--allow-env`,
  including the startup set (`PATH`, `HOME`, `TERM`, `LANG`, `LC_ALL`, `LC_CTYPE`,
  `TZ`) the CLI grants so that a program named without a leading `/` is looked up
  in your `PATH` rather than only in the C library's fallback. The value arrives
  whole — see *A variable you pass through is passed in full* above.
- A command reading or executing files under a path you granted with
  `--allow-read`, including system binaries granted by default so that commands
  can start at all.
- A command *reading* a path you granted with `--allow-write` on the command
  line. The `sandbx` CLI grants read alongside write, because a tool that can
  rewrite a tree but not read it back is a trap rather than a safeguard. The
  library keeps the two axes separate, so a genuinely write-only drop directory
  is still expressible through `SandboxPolicy::allow_write`.
- An agent running a tool call — one you approved, or, as things stand, any one the
  model asked for, since nothing gates them yet (see *Approval is not enforcement*
  above). That includes a call a prompt injection induced, and it includes one
  reached through `agent-run`, which is a real path and not a library-only one.
  What bounds it is the sandbox, not the asking.
- Refusal to run on a kernel older than 6.10, or on one with Landlock disabled at
  boot. That is fail-closed behaviour working as intended.
- Failure to *build* for a non-Linux target. Also intended — see above.
- Refusal to run where unprivileged user namespaces are disabled. The PID
  namespace that bounds a command's descendants needs one, whatever the policy
  says, so this is the same fail-closed behaviour rather than a lost feature.
- A descendant surviving the call because the command both had its parent death
  signal cleared by a secure `exec` *and* called `setsid` to leave the process
  group. Both would have to happen together, and a survivor is still fully
  confined — Landlock, seccomp and the namespaces are irreversible and
  inherited — so it is unreaped, not unrestricted.
