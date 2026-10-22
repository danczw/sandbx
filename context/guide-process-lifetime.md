# Process lifetime

Nothing the sandbox starts may outlive the call that started it (#28).

## Three processes

| # | Process | Job |
|---|---|---|
| 0 | `sandbx` | spawns stage 1; **when a timeout is set**, in its own process group, polls the deadline, `killpg` |
| 1 | helper supervisor | `unshare(NEWUSER\|NEWPID[\|NEWNET])`, uid/gid map, drop capsets, `RLIMIT_CORE=0`, `no_new_privs`, then `exec` stage 2 |
| 2 | helper inner | PID 1 of the new namespace, and stays it. `pdeathsig`, confirm supervisor, `apply()`, non-dumpable, spawns the command, reaps until it exits |

Stage 1 exists because `unshare(CLONE_NEWPID)` only places a process's
*children* — so unsharing in the supervisor is what makes stage 2 PID 1. Stage 2
is a second `exec` of the helper rather than a `fork`, which would need `unsafe`.

Of stage 1's work, `uid/gid map` and the capability **bounding** set drop are
*best-effort*: both record an `AuditEvent::Degraded` and carry on. Everything
else there is a hard failure.

## The kill chain

```
deadline fires ──► killpg(SIGKILL) on the group
       │
       ├─ stage 2 dies (it is in the group too)
       └─ stage 1 dies ──► stage 2's pdeathsig fires ──► stage 2 dies
                                  │
                                  └─ stage 2 was PID 1 ──► kernel SIGKILLs the whole namespace
```

Two independent paths reach stage 2 on purpose: the group kill, and `pdeathsig`
when stage 1 dies without one — killed by hand, or on an untimed call. Both end
**stage 2**, never the command, and that is the point.

## Why stage 2 is the init, not the command

The command can shed both paths from itself. `setsid` leaves the group (#28).
`pdeathsig` is per *thread*: a new thread starts with it at 0, so an `exec` from
a second thread hands PID 1 an image that has none, with no `prctl` to filter
(#272). The kernel also clears it on a secure `exec`. A process that runs
arbitrary code cannot be the one the kill chain rests on.

So stage 2 spawns the command and stays PID 1: it never calls `setsid`, never
`exec`s and stays single-threaded, so both paths keep reaching it. It reaps
orphans until the command exits, then exits as the command did, and its exit is
what tears the namespace down — the shape of bubblewrap's `do_init`.

Three things follow:

- **The init is non-dumpable.** It applies the ruleset before spawning, so it
  shares the command's Landlock domain, which permits `/proc/<pid>/mem` and
  `environ` across the domain. `PR_SET_DUMPABLE` 0 makes those need
  `CAP_SYS_PTRACE`; it holds because the init never `exec`s.
- **A signalled command reports as `128 + n`.** An init cannot die by a signal it
  raises at itself, so the status loses its signalled form on the way out.
  `exit_code` gives the same number either way.
- **The command is PID 2, its parent PID 1**, and receives signals normally.

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
completion in a namespace no one is watching.

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

Every signal the command dies by surfaces as `128 + n`, the init exiting with
that number rather than dying by it — see above.

`unshare`, `setns` and `mount` are all in the seccomp denylist, so the command
cannot build itself a new namespace or remount `/proc` out from under any of
this. `clone` reaches those same namespaces through its flags argument, so it is
filtered per flag; `clone3`, whose flags sit behind a pointer seccomp cannot
follow, answers `ENOSYS` so callers fall back to the filtered `clone`.

## What this does NOT do

A fork bomb still runs unbounded for the length of the call — **cgroups are not
in place**, and nothing limits process count, memory or CPU.

That is about *spawned processes*. Tool work is bounded separately; see
`decision-bounding-tool-work.md`.
