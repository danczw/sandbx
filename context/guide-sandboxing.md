# Sandboxing

What `sandbx-core` enforces, and how. `SECURITY.md` is the promise to users;
this is the mechanism behind it. Where they disagree, `SECURITY.md` wins and
this file is the bug.

## The three primitives

| Mechanism | Bounds | Where |
|---|---|---|
| Landlock | filesystem paths | `helper/ruleset/rights.rs` |
| seccomp-BPF | syscalls | `helper/seccomp.rs` |
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

## Failure is closed

One ABI, hard-required, or nothing:

```
negotiated_abi()            NEGOTIABLE_ABI = [V9, V8, V7, V6, V5], newest first
   │
   ├─ handle_access(from_all(abi)) under HardRequirement
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
  Landlock leaves an unhandled access type unrestricted *everywhere*.
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
negotiated_abi()
  ruleset + fs_rules(policy, abi) ──► PathFd::new ──► add_rule
restrict_self()
enforcement_verdict()
```

Order is required, not incidental. `apply` is the one place all three mechanisms
are sequenced; seccomp precedes Landlock because the filter needs `no_new_privs`
first.

A dir-only right on a regular file **fails `add_rule`** under `HardRequirement` —
so the `& from_file(abi)` narrowing is not a tidying step. Dropping it would
refuse every policy naming a regular file, which `--allow-read ./config.toml`
does. It does not degrade quietly; there is no quiet left to degrade into.

## Syscall denylist

28 entries in `BLOCKED_SYSCALLS`; the filter is built from that list and nothing
else. 4 have real-kernel probes in `tests/enforcement.rs` (`io_uring_setup`,
`memfd_create`, `pidfd_open`, `pidfd_getfd`); the other 24 rest on the list plus
`tests/denylist.rs`, which asserts the documented set against it.

`EPERM`, not kill — a denied syscall should look like a permission error to the
program, not a crash. `socket(AF_UNIX)` is gated on `allows_unix_sockets()`,
independently of `allows_network`; `socketpair` is left alone.

## Namespaces and process state

| Step | Hard or best-effort | Note |
|---|---|---|
| `unshare(CLONE_NEWUSER\|CLONE_NEWPID[\|CLONE_NEWNET])` | **hard** — EPERM refuses | unconditional for every policy |
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
        └──► env::restrict(&mut Command, &policy)
                 env_clear()
                 envs(allowed_env ∩ live environment)      unset name ⇒ absent
```

Applied at **all four** spawn sites, not just the last:

```
sandbx ──► helper stage 1 ──► stage 2 ──► the command
       ↑               ↑            ↑             ↑
   output()      run_with_        re-exec      .exec()   ◄── the load-bearing one
                 deadline()
```

`restrict` is idempotent — after the first clear the environment already *is* the
allowlist — which is what makes repeating it free. The first three keep a secret
out of a helper's `/proc/<pid>/environ` for the seconds it lives; the last decides
what the real command can read out of its own. Stages 1 and 2 doing it themselves
is why a helper invoked **directly**, with no `sandbx` above it, is sanitised
rather than trusted.

`default()` is empty, so there is no `PATH` unless something grants one, and a
bare program name is then resolved against the C library's fallback
(`/bin:/usr/bin` on glibc) — `cat` starts, `/usr/local/bin/anything` is not
found. The CLI calls
`allow_standard_env()`; library callers either do the same or pass an absolute
path, as every test in `crates/sandbx-core/tests/` does. Rationale in
`decision-environment-allowlist.md`.

## What this does NOT protect against

Matches `SECURITY.md`'s known-weaknesses table. The short form:

- **No resource bounds on spawned processes.** A fork bomb runs unbounded for the
  length of the call; cgroups are not in place. Tool *work* is bounded — see
  `decision-bounding-tool-work.md` — but that is a different axis.
- **The bounding set may be left as inherited.** It cannot be spent (the other
  four sets are empty and `no_new_privs` is set), so a leftover bit never becomes
  privilege. Do not rely on `CapBnd` being empty.
- **A dependency is not contained.** Anything linked into the binary runs with
  the harness's privileges.
- **No approval step exists.** The sandbox is the only thing between a
  prompt-injected tool call and your files.
- **`unsafe` is forbidden workspace-wide** and spawning outside `sandbx-core` is
  a clippy error, but convention plus tooling is not a capability system.
- **A variable passed through is passed whole.** The environment allowlist is by
  name; there is no redaction and no per-tool scoping, and every descendant
  inherits it. Credential injection without exposing the value is #41.
- **The policy is readable from inside.** Granted paths and allowlisted variable
  names cross as argv, and the command can read `/proc/self/cmdline`. Names only,
  never values — which is why there is no `--allow-env NAME=VALUE`.

## Known gaps

| Gap | State |
|---|---|
| Per-socket unix grants | **open**. Needs Landlock `ResolveUnix` (ABI V9, Linux 7.1). `negotiated_abi` hard-requires a whole level, so V9 brings no automatic narrowing — the grant has to be written. Today it is one all-or-nothing toggle. |
| `FsGuard` TOCTOU | **mostly closed**. Tools take handles (`open_read`/`open_write`, `O_NOFOLLOW`), not resolved paths. Residual: a parent-directory swap mid-open, which needs full `openat`-chain resolution. `ls` still takes a path — `read_dir` has no handle form. |
| Capability coverage | **closed**. `tests/capability_coverage.rs` reads `/proc/sys/kernel/cap_last_cap`, so a kernel adding a capability the `caps` crate does not know about is a test failure, not a silent leftover. |

## Host environment

AppArmor's `restrict_unprivileged_userns` (default on Ubuntu 24.04+) is the
reason the two best-effort steps exist. A dev box without AppArmor cannot
exercise either path — capability and userns behaviour is only provable on CI.
