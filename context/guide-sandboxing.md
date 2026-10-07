# Sandboxing

What `sandbx-core` enforces, and how. `SECURITY.md` is the promise to users;
this is the mechanism behind it. Where they disagree, `SECURITY.md` wins and
this file is the bug.

## The three primitives

| Mechanism | Bounds | Where |
|---|---|---|
| Landlock | filesystem paths, and TCP ports | `helper/ruleset/rights.rs` |
| seccomp-BPF | syscalls, down to a socket's domain, type and protocol, a socket option's name and a send's flags | `helper/seccomp/rules.rs` |
| namespaces | network, PIDs, identity | `helper/hardening.rs` |

## Two layers, one table

Both enforcement layers derive from `Axis::grants()` in `policy.rs` — **the
table**. Adding an axis is adding a row; the compiler then names every site
that cannot derive its answer from one.

| Axis | read | write | execute | CLI flag |
|---|---|---|---|---|
| `Read` | ✓ | | | `--allow-read` |
| `Write` | | ✓ | | `--allow-write` |
| `ReadExecute` | ✓ | | ✓ | `--allow-exec` |

The asymmetry runs one way: `ReadExecute` confers read (a program needs the
binary *and* the libraries its loader pulls in), no grant confers execute, and
write confers neither.

`--pin-sha256` is deliberately not a row. It grants nothing and neither layer
derives anything from it — it narrows which bytes one `execve` may run, checked in
`digest.rs` against a descriptor rather than by the kernel. Why, in
`context/decision-pinned-entry-point.md`.

**Which layer sees which tool:**

```
read/write/edit/ls/grep/find  ──►  FsGuard (in-process)   ──►  never reaches Landlock
bash                          ──►  helper re-exec         ──►  Landlock + seccomp + netns
```

Six of seven built-ins never spawn anything, so Landlock never sees them.
`FsGuard` is the *only* filesystem enforcement for those — a second consumer of
the same table (`fs_guard.rs`), sorting grants into readable/writable roots and
discarding `execute`. #49/#50 were the two layers answering differently for one
policy; the shared table is the fix.

> **The CLI grants read alongside write.** `--allow-write ~/project` also grants
> `Read`, because at a command line the separation is a trap — a tool could
> rewrite the tree and then fail to `cat` it back. Keyed to `axis.grants().write`,
> not to the `Write` variant, so a future write-conferring axis inherits it.
> **Only `SandboxPolicy::allow_write` is narrow**; a write-only drop directory is
> reachable through the API, not the CLI (#49).

## Landlock rights

```
allow_read     ──►  from_read(abi) & !Execute
allow_write    ──►  from_all(abi)  & !from_read(abi)      ◄── the whole read set, not just Execute
allow_exec     ──►  from_read(abi) & !Execute | Execute
non-directory  ──►  rights & from_file(abi)               ◄── narrowed once more
```

`abi` is the *negotiated* level, not `LATEST` — that is what makes the mapping
kernel-independent. Subtractions rather than enumerations: a new right added by
a future ABI lands in `from_all` and is therefore denied by `allow_read`
automatically, instead of being silently permitted until someone notices.

The network axis is a separate set, `AccessNet`, and does not compose with the
above — `BitFlags<AccessFs>` and `BitFlags<AccessNet>` are distinct types:

```
Denied    ──►  Unhandled              ◄── the empty netns confines it instead
AnyPort   ──►  Unhandled              ◄── the flag's stated meaning
Ports(p)  ──►  Ports { handled: from_all(abi), granted: BindTcp | ConnectTcp, p }
```

`handled` and `granted` are deliberately not the same set — the two directions
are not symmetric. A right a future ABI adds has to be *handled*, or Landlock
leaves it unrestricted everywhere; but granting it on every allowlisted port is
how a UDP or raw right would arrive already permitted on the ports the policy
named. So the axis is policed in full and a port rule confers those two rights
and nothing else.

`Unhandled` is a named state and not an empty collection, which is the one thing
in this file most worth not simplifying. Handling `AccessNet` with zero
`NetPort` rules denies *all* TCP; not handling it leaves TCP *unrestricted*. So
"no net rules" is two opposite behaviours, and an `Option` or a `Vec` would spell
the fail-open one by default.

## Failure is closed

One ABI, hard-required, or nothing:

```
negotiated_abi_from(probe)  NEGOTIABLE_ABI = [V9, V8, V7, V6, V5], newest first
   │                        probe = kernel_probe in production, a closure in tests
   ├─ handle_access(handled_access(abi)) under HardRequirement
   │     ├─ Ok                        ──► settle on this abi
   │     ├─ Err(HandleAccesses(_))    ──► step down one rung   ◄── the only steppable error
   │     └─ Err(other)                ──► refuse
   │
   └─ ladder exhausted  ──► refuse: "ABI 5, Linux 6.10; refusing to run unconfined"

restrict_self() ──► enforcement_verdict(status)
                      FullyEnforced      ──► Ok
                      PartiallyEnforced  ──► refuse   ◄── #76
                      NotEnforced        ──► refuse
```

Two things make this fail-closed rather than fail-quiet:

- **A non-verdict error is a refusal.** Stepping down on it would hand back a
  lower ABI than the kernel has, leaving every right above it unhandled — and
  Landlock leaves an unhandled access type unrestricted *everywhere*. The walk is
  split from the kernel it walks (`negotiated_abi_from` takes the probe), so this
  discrimination is decidable with no Landlock host; replacing the refusing arm
  with `continue` used to leave both suites green and both CI jobs passing (#87).
  Two refusals that stay distinguishable: `Unsupported` names the ABI floor,
  `Landlock` carries the kernel's own reason.
- **Partial enforcement is a refusal** (#76). `enforcement_verdict` is total over
  `RulesetStatus`, so a variant added by a future landlock release fails to
  compile rather than landing in an accepting arm. The old `== NotEnforced`
  check let `PartiallyEnforced` through for as long as that variant existed.

There is no pre-flight probe in sandbx itself. The check runs inside helper
stage 2, so an unsupported kernel surfaces as the helper's non-zero exit, not as
an in-process `Err`. `Ruleset::create()` does not restrict, which is what lets
the ladder walk in one process.

## `apply` sequence

```
set_no_new_privs()        ◄── seccomp will not install without it
deny_dangerous_syscalls(policy)
requested(policy)  ──► Requested { handled, rules, net }   ◄── negotiates internally
  handle_access(handled)
  net == Ports  ──► handle_access(net handled)       ◄── both before create
                                   create
  for rules: PathFd::new ──► add_rule
  net == Ports  ──► for ports: NetPort::new(port, granted) ──► add_rule
restrict_self()
enforcement_verdict()
```

Order is required, not incidental. `apply` is the one place all three mechanisms
are sequenced; seccomp precedes Landlock because the filter needs `no_new_privs`
first.

`negotiated_abi` is no longer a step of its own: the handled set and the rules
have to come from *one* ABI, and `apply` used to derive them from two separate
expressions with only a comment saying they must agree (#87). `requested`
negotiates and returns both, so no ABI is in scope in `apply` at all and the
divergence is unexpressible rather than merely commented against. `Access` and
`AccessFs` dropped out of `apply`'s imports with it, so reintroducing the split
means reintroducing two imports — visible in a diff.

The network axis is split across `create` because Landlock is: `handle_access`
exists only before it and `add_rule` only after. So `apply` destructures `net`
once and gates both uses on the same `Option`, which is the whole of why there
is no path that installs a port rule without handling the axis, or handles it
for a policy that asked for no ports. Getting that wrong in the second direction
is loud; getting it wrong in the first leaves TCP unrestricted while the CLI
reports an allowlist, and only `tests/enforcement_network.rs` sees it.

A dir-only right on a regular file **fails `add_rule`** under `HardRequirement` —
so the `& from_file(abi)` narrowing is not a tidying step. Dropping it would
refuse every policy naming a regular file, which `--allow-read ./config.toml`
does. It does not degrade quietly; there is no quiet left to degrade into.

## Syscall denylist

28 entries in `BLOCKED_SYSCALLS`; the filter is built from that list and nothing
else. Three rungs of evidence, strongest first:

| Rung | Where | Covers |
|---|---|---|
| a real kernel refuses the call | `tests/enforcement_syscalls.rs` | 4 of the 28 — `io_uring_setup`, `memfd_create`, `pidfd_open`, `pidfd_getfd` — and, separately, the `socket(AF_UNIX)` rule, which is not a list entry |
| the compiled program returns `EPERM` for it | `eval` in `helper/seccomp/tests/mod.rs` | all 28, plus what the `AF_UNIX`, `clone`-flag and x32 rules compare against |
| the documented set matches the list | `tests/denylist.rs` | all 28 |

The middle rung is a test-only classic-BPF interpreter run over a synthetic
`seccomp_data`, which is why it can cover every entry without spawning anything.
What it establishes is what sandbx *asked the kernel for*. It is not what the
kernel does: the effective action is the most severe across every installed
filter, so a program returning `ALLOW` is not a syscall that runs, and nothing
here proves the kernel loads the program at all. That stays `enforcement.rs`'s
job. It replaced two tests that read the program's instruction *layout* — the
coupling to seccompiler's codegen is relocated into `eval`, not removed, and
`eval` panics by name on an opcode it does not implement rather than guessing a
verdict (#99).

`EPERM`, not kill — a denied syscall should look like a permission error to the
program, not a crash. `socket` carries two independent families of rule, so both
append with `entry().or_default()` rather than `insert` — rules for one syscall
are OR'd, and an `insert` in either would wipe the other silently. The
`AF_UNIX` denial is gated on `allows_unix_sockets()`, independently of
`allows_network`; the type, family and protocol denials are gated on
`NetworkPolicy::Ports` alone, as is the `TCP_ULP` rule on `setsockopt` — the
family of a socket is not fixed at `socket` time — and the `MSG_FASTOPEN` rules
on the send syscalls. `context/decision-port-allowlist.md` is why.
`socketpair` is left alone.

### Three filters, three actions

The list above is one of three stacked filters on x86\_64 — two elsewhere, the
x32 gate being x86\_64-only — because a seccompiler filter carries a single match
action and two rules need a different one. The kernel takes the most severe
verdict across all of them, so install order means nothing and a later filter
cannot loosen an earlier one.

| Filter | Action | Why not `EPERM` |
|---|---|---|
| the 28 entries, the conditional `socket`, `setsockopt`, `sendto` and `sendmsg` rules, `clone` with a `CLONE_NEW*` flag | `EPERM` | — |
| `clone3` | `ENOSYS` | glibc 2.34+ calls it from `pthread_create` and falls back to `clone` only on `ENOSYS`; `EPERM` breaks every threaded program instead of routing it onto the filtered `clone` |
| any non-negative `nr` carrying `__X32_SYSCALL_BIT`, x86\_64 only | kill | a foreign ABI whose numbers mean something else, so no per-call verdict is meaningful — the same reason the architecture gate kills |

`clone` closes what denying `unshare` alone did not: the same namespaces are
reachable through its flags argument (#118). One rule per flag, because rules
for a syscall are OR'd while conditions inside a rule are AND'd — a single
`MaskedEq` over the union would fire only when every flag was set. `Dword`, so
the comparison ignores a high half the kernel also ignores. `CLONE_NEWTIME` is
absent because `clone` cannot honour it: `0x80` falls inside `CSIGNAL`, and
`SYSCALL_DEFINE5(clone)` takes `lower_32_bits(flags) & ~CSIGNAL`, so the bit is
dropped and no time namespace is created — the call succeeds rather than failing,
so do not read a refusal into it. `unshare` and `clone3` do honour the flag, and
both are denied outright.

x32 is denied as an ABI rather than enumerated (#117). It reports
`AUDIT_ARCH_X86_64`, so it passes the architecture gate, and its numbers are the
native ones with bit 30 set — except `ptrace`, `kexec_load`, `process_vm_readv`
and `process_vm_writev`, which sit at *different* x32 numbers again. A mask over
`nr` covers the list as it grows; a list of x32 numbers would not. It is
hand-assembled classic BPF because seccompiler's conditions address syscall
arguments, and `nr` is reachable only as a filter key.

The mask alone is not enough: `syscall(-1)` is `0xffff_ffff`, which carries bit
30, and killing it would turn an `ENOSYS` every kernel returns into death by
signal. The gate excludes a set sign bit first — `do_syscall_64` special-cases
`nr == -1`, and x32 dispatch is `nr - BIT < X32_NR_syscalls`, so nothing
negative is x32. A positive number past the end of the x32 table is still
killed: matching the table exactly would mean pinning its size in sandbx, and
only an x32 caller reaches for those numbers.

## Namespaces and process state

| Step | Hard or best-effort | Note |
|---|---|---|
| `unshare(CLONE_NEWUSER\|CLONE_NEWPID[\|CLONE_NEWNET])` | **hard** — EPERM refuses | unconditional for every policy; `CLONE_NEWNET` is dropped whenever network is granted *at all*, a bare grant and a port allowlist alike, because a port rule inside an empty netns has nothing to permit |
| `no_new_privs` | **hard** | set in both stages |
| effective/permitted/inheritable/ambient capsets | **hard** | |
| `RLIMIT_CORE = 0` | **hard** | chosen over `PR_SET_DUMPABLE`: only the rlimit survives `execve` |
| capability **bounding** set | *best-effort* | needs `CAP_SETPCAP`; AppArmor strips it |
| userns identity map | *best-effort* | denied write leaves the process as overflow `nobody` |

Both best-effort steps record an `AuditEvent::Degraded` at `INFO` when they
fail. They fail on whole classes of host rather than intermittently, so the run
where it matters is not the one where someone thought to raise the log level.

`/proc/self/setgroups` must be written `deny` before the unprivileged `gid_map`
write, or the kernel rejects it. Correct anyway: one gid is mapped, so there are
no supplementary groups to set.

Bounding set is dropped *before* the effective set — `PR_CAPBSET_DROP` itself
needs `CAP_SETPCAP` in effective.

## The command's environment

A fourth bound, and the one none of the three primitives can reach: the kernel
hands the environment over during `exec`, before any Landlock ruleset or seccomp
filter the new image installs has a say. So it is enforced by *not passing it*
(#98).

```
SandboxPolicy { env: Vec<String> }        names only, never values
        │
        └──► spawn::command(program, &policy) -> Command
                 Command::new(program)                     the only one in the workspace
                 env_clear()
                 envs(allowed_env ∩ live environment)      unset name ⇒ absent
                 envs(imposed_env)                         constants, and the last word
```

Not applied *at* the four spawn sites — it is what builds them. All four get their
`Command` from `spawn::command`, so narrowing is a property of construction rather
than a call each site has to remember:

```
sandbx ──► helper stage 1 ──► stage 2 ──► the command
       ↑               ↑            ↑             ↑
   output()      run_with_        re-exec      .exec()   ◄── the load-bearing one
                 deadline()
       └──────────────┴────────────┴─────────────┘
                  all four via spawn::command
```

`clippy.toml` bans `std::process::Command::new` workspace-wide, and
`spawn::command` holds the single `#[allow]` for it — so a fifth spawn site does not
compile unless it goes through the narrowing. The first three keep a secret out of a
helper's `/proc/<pid>/environ` for the seconds it lives; the last decides what the
real command can read out of its own. Stage 1 narrowing on the way in is why a
helper invoked **directly**, with no `sandbx` above it, is sanitised rather than
trusted.

Stage 2 is the one that does not trust its input: before applying anything it
refuses outright if it finds a variable the policy neither names nor imposes in the
environment it *inherited*, because on every supported path stage 1 has already
cleared it. Both sides ask `permits_env`, so what the factory puts there cannot be
what this refuses. So a
*direct* stage-2 invocation is refused rather than sanitised — the one place the two
stages differ, and what makes the clear something a test can catch the absence of
rather than merely something the code does.

`default()` is empty, so there is no `PATH` unless something grants one, and a
bare program name is then resolved against whatever default the lookup falls back
to — `execvp`'s is the C library's (`/bin:/usr/bin` on glibc), a shell's is its
own compiled-in one (wider: dash and bash include `/usr/local/bin` and the `sbin`
directories). So `cat` starts either way, `~/.cargo/bin/anything` starts neither
way, and `/usr/local/bin/anything` depends on which spawned it. Partial and
inconsistent, which is the reason to grant `PATH` rather than reason about it. The
CLI calls
`allow_standard_env()`; library callers either do the same or pass an absolute
path, as every test in `crates/sandbx-core/tests/` does. Rationale in
`decision-environment-allowlist.md`.

## What this does NOT protect against

Matches `SECURITY.md`'s *What sandbx does not claim*. The short form:

- **No resource bounds on spawned processes.** A fork bomb runs unbounded for the
  length of the call; cgroups are not in place. Tool *work* is bounded — see
  `decision-bounding-tool-work.md` — but that is a different axis.
- **The bounding set may be left as inherited.** It cannot be spent (the other
  four sets are empty and `no_new_privs` is set), so a leftover bit never becomes
  privilege. Do not rely on `CapBnd` being empty.
- **A dependency is not contained.** Anything linked into the binary runs with
  the harness's privileges.
- **Approval is per tool per run.** The gate narrows which tools a hijacked turn
  can use; once one is approved, the sandbox is the only thing between a
  prompt-injected call to it and your files. No per-call prompt (#165).
- **`unsafe` is forbidden workspace-wide** and spawning outside `sandbx-core` is
  a clippy error, but convention plus tooling is not a capability system.
- **A variable passed through is passed whole.** The environment allowlist is by
  name; there is no redaction and no per-tool scoping, and every descendant
  inherits it. One name is refused rather than passed — `agent-run` will not take
  `--allow-env ANTHROPIC_API_KEY` — and that is the whole of it; handing a tool a
  credential without exposing the value has no mechanism, and
  `decision-tool-credentials.md` says why none is claimable.
- **The policy is readable from inside.** Granted paths and allowlisted variable
  names cross as argv, and the command can read `/proc/self/cmdline`. Names only,
  never values — which is why there is no `--allow-env NAME=VALUE`, and why
  `--dns-over-tcp` crosses as a flag rather than as the pair it stands for.
- **A port allowlist is not a destination allowlist.** Landlock matches the port
  and nothing else, so `--allow-network 443` reaches port 443 on every routable
  host. Per-host needs a userspace proxy, whose interception is cooperation rather
  than enforcement — `decision-egress-proxy.md` prices every piece of it, and
  carves out the one that is claimable (#145).
- **A port allowlist is not uniformly narrower than withholding network.** It
  refuses `bind` on every unlisted port, `bind(0)` included, and it shares the
  host's netns where `Denied` had an empty one — so host loopback is reachable.
  That, and the denials that make the port claim true at all, in
  `decision-port-allowlist.md`.

## Known gaps

| Gap | Residual |
|---|---|
| Per-host egress | **No kernel mechanism matches a destination** (#145). Per-*port* does — Landlock TCP port rules plus a seccomp denial of UDP, raw sockets, non-TCP stream protocols, IP-tunnelling families, `TCP_ULP` conversion and TCP Fast Open — so per-host means terminating connections in a proxy sandbx does not have, and that proxy is declined rather than pending: its interception is cooperation and TLS termination widens the boundary it would narrow, per `decision-egress-proxy.md`. What that note carves out is a resolver bounding which *names* resolve, which is not a destination control. The UDP denial breaks name resolution, which `--dns-over-tcp` routes around under glibc and not under musl. |
| Per-socket unix grants | **Needs Landlock `ResolveUnix`** (ABI V9, Linux 7.1). `negotiated_abi` hard-requires a whole level, so V9 brings no automatic narrowing — the grant has to be written. It is one all-or-nothing toggle. |
| `FsGuard` TOCTOU | **A parent-directory swap mid-open**, which needs full `openat`-chain resolution. `open_read`/`open_write` take handles with `O_NOFOLLOW`, but `ls`, `grep` and `find` resolve paths — `read_dir` has no handle form, and `walk_readable` checks the walk root alone, so every directory below it is reopened by path. |
| Capability coverage | **Pinned by `tests/capability_coverage.rs`**, which reads `/proc/sys/kernel/cap_last_cap`, so a kernel adding a capability the `caps` crate does not know about is a test failure, not a silent leftover. |
| `Degraded` raised by nothing a test enters | **Pinned on any host.** Both best-effort steps take their fallible call as a parameter, so a refusal becoming a record is asserted anywhere; `tests/audit_channel.rs` then asserts the record is present or absent according to the LSM — see *Host environment*. |

## Host environment

AppArmor's `restrict_unprivileged_userns` (default on Ubuntu 24.04+) is the
reason the two best-effort steps exist. A dev box without AppArmor cannot make
either step fail, so what is provable where is split in two: that a refusal
becomes a `Degraded` record is asserted everywhere, through the seams
`drop_bounding_set` and `map_identity_into_userns_with` take their fallible call
as a parameter for; that the kernel refuses at all is only observable on a host
with the restriction, which the CI runner has.
