# Process lifetime

Nothing the sandbox starts may outlive the call that started it (#28).

## Three processes

| # | Process | Job |
|---|---|---|
| 0 | `sandbx` | spawns stage 1; **when a timeout is set**, in its own process group, polls the deadline, `killpg` |
| 1 | helper supervisor | `unshare(NEWUSER\|NEWPID[\|NEWNET])`, drop capsets, `RLIMIT_CORE=0`, `no_new_privs`, uid/gid map, then `exec` stage 2 |
| 2 | helper inner | PID 1 of the new namespace. `pdeathsig`, confirm supervisor, `apply()`, then becomes the command |

Stage 1 exists because `unshare(CLONE_NEWPID)` only places a process's
*children* — so unsharing in the supervisor is what makes stage 2 PID 1.

Of stage 1's work, `uid/gid map` and the capability **bounding** set drop are
*best-effort*: both record an `AuditEvent::Degraded` and carry on. Everything
else there is a hard failure.

## The kill chain

```
deadline fires ──► killpg(SIGKILL) on the group
       │
       └─ stage 1 dies ──► stage 2's pdeathsig fires ──► stage 2 dies
                                  │
                                  └─ stage 2 was PID 1 ──► kernel SIGKILLs the whole namespace
```

Two independent paths reach stage 2 on purpose. The supervisor and stage 2 are
both in the group sandbx kills — but the command may call `setsid` and leave it,
which is the whole of #28. `pdeathsig` does not care about group membership. The
kernel clears it for a secure `exec` (setuid, file capabilities), where the group
kill is then what still reaps.

**The group kill fires on every timed run, not only on expiry.** A command may
background work and exit inside its deadline while its descendants still hold the
pipe write-ends.

## Arm, then confirm

```
bind_lifetime_to_supervisor()   ← arm pdeathsig
confirm_supervisor(expected)    ← then check
```

Ordering is what makes the pair complete. A death *before* the check is caught by
the check; a death *after* it is caught by the signal already armed. Reverse them
and there is a window where nothing kills stage 2 and the command runs to
completion as PID 1 of a namespace no one is watching.

`getppid()` is useless here — stage 2 is PID 1 of a namespace whose parent is
outside it, so the kernel returns 0. `/proc` is still the host's procfs (not
remounted: `mount(2)` is denied), so field 4 of `/proc/self/stat` names the
supervisor in host numbering. `ppid_from_stat` parses it by splitting after the
**last** `)`, because field 2 is an unquoted executable name free to contain
spaces and parens — and it is a separate function so that the unit tests beside
it can hand it such a name without a supervisor or a namespace.

Pid reuse cannot produce a false pass: the comparison is against the kernel's
live parent link, and an orphan reparents to init or a subreaper, neither of
which can be the pid of a supervisor that just spawned us.

## Two bounds, not one

| Bound | Value | Promises |
|---|---|---|
| namespace teardown | — | no descendant outlives the call, **even with no timeout set** |
| `DRAIN_GRACE` | 200 ms | the call returns even if a descendant still holds the pipe |

`settle` waits at most `DRAIN_GRACE` for the pipe readers, then abandons them —
output still in flight is dropped. A promise about the call returning, not about
who is still running. `POLL_INTERVAL` is 10 ms.

> **The untimed path has neither a process group nor a kill.** `output()` without
> a deadline is a plain `Command::output()`; nothing fires on that path at all,
> and namespace teardown is the only mechanism left.

## Signals

Stage 2 does not call `setsid`, which is what keeps it in the group sandbx kills.

The relay cannot re-raise `SIGPIPE`, `SIGSEGV` or `SIGBUS`, so those surface as
`128 + n` rather than as a real death by that signal.

`unshare`, `setns` and `mount` are all in the seccomp denylist, so the command
cannot build itself a new namespace or remount `/proc` out from under any of
this.

## What this does NOT do

A fork bomb still runs unbounded for the length of the call — **cgroups are not
in place**, and nothing limits process count, memory or CPU.

That is about *spawned processes*. Tool work is bounded separately; see
`decision-bounding-tool-work.md`.
