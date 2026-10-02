# The helper's audit channel

Why a degradation detected inside the sandbox helper crosses back to sandbx as
bytes in the **stdin slot** rather than being logged where it is found (#95).

## The problem

`AuditEvent::Degraded` has two emitters, both in `helper/hardening.rs`:
`PR_CAPBSET_DROP` refused, and the uid/gid map unwritten. Both run in helper
**stage 1**, a re-exec'd child of sandbx.

That process installs no `tracing` subscriber. `logging::init()` is called inside
the `with_helper_dispatch` closure, which runs only for
`HelperDispatch::NotHelperMode`; the helper routes into `exec_sandboxed` and never
returns. `tracing` drops an event with no subscriber silently and at every level,
so the record reached nobody.

The placement is not an oversight — it is load-bearing. Stage 1's stdout and stderr
are pipes sandbx captures and replays verbatim, and stage 2 inherits them before
becoming the command. A subscriber in the helper would write sandbx's own audit
records into the output of the command being sandboxed.

So #89's level change (`debug!` → `AuditEvent` at `INFO`) bought nothing: a record
that survives the filter still needs somewhere to land. On Ubuntu 24.04+ hosts,
where AppArmor's `restrict_unprivileged_userns` makes the bounding-set drop fail by
default, `SECURITY.md` promised the operator a signal they never got.

## Why not a descriptor of its own

The issue's first option was an inherited fd at a number passed in argv. It is not
reachable here: `unsafe_code = "forbid"` is workspace-wide (`Cargo.toml`), and
adopting a raw fd child-side needs `OwnedFd::from_raw_fd` or
`BorrowedFd::borrow_raw`, both `unsafe`.

Checked by experiment rather than assumed. A non-CLOEXEC fd *does* survive
`Command::spawn` and the following `exec`, and `nix::fcntl(F_SETFD)` can clear
CLOEXEC safely on the parent side — so the kernel half works. It is the safe
*adoption* that does not exist. The only descriptors `std` hands a child without
`unsafe` are 0, 1 and 2.

The second option — report in-band through the existing protocol — is also
unavailable. `HelperArgs` is argv, which is one-directional, and stage 1's exit
status is the *command's*, relayed faithfully by `helper::relay`; spending it on a
hardening note would misreport what the command did.

The third — a subscriber in the helper — is the thing the current placement exists
to prevent, and was already rejected.

That leaves fd 0. 1 and 2 are the command's output.

## The shape

```
sandbx                      stage 1                 stage 2 / command
------                      -------                 -----------------
io::pipe() ──┐
             └─ write ──►   stdin (fd 0)
                            │ capability_bounding_set\tleft as inherited: EPERM
                            ├─ drops its handle
                            └─ spawns ────────────► stdin = Stdio::null()
reads to EOF                                        (no path to the channel)
  └─ AuditEvent::degraded(..).emit()
```

`hardening.rs` returns `Vec<(Degradation, String)>` instead of emitting;
`degradation.rs` owns the format and both ends; `exec_sandboxed` performs the one
write; `command.rs` reads, decodes and emits.

**sandbx emits, not the helper.** One subscriber in the process tree, one timestamp
source, one format, and no `tracing-subscriber` dependency in the helper. This is
the property the issue wanted from its in-band option, obtained over a channel.

**`--sandbx-audit-stdin` makes it opt-in.** Positional and split off before
`HelperArgs::decode`, which refuses flags it does not recognise — the same
treatment the supervisor pid gets in `exec_inner`, and for the same reason: it
describes how to report, not what the command may do. Without the flag a helper run
by hand writes audit text into whatever fd 0 happens to be — a terminal is
writable, so the records would look like the command's own output, and a read-only
pipe gives `EBADF`. `SandboxedCommand` always passes it because it always sets the
pipe up.

**`Stdio::null()` on the inner stage is the security line.** Stage 1 becomes
nothing, but stage 2 becomes the sandboxed command, and an inherited write end
would let it forge records on sandbx's audit trail — or hold the pipe open and
leave sandbx waiting on an EOF that never comes.

It is pinned by `the_sandboxed_command_cannot_write_the_audit_channel`, and the
test was checked by removing the line: without it the command's `printf` lands on
the trail as `decision=degraded mechanism=capability_bounding_set`. That check also
caught a flaw in the test's own first draft — a literal tab in the script is an
`IFS` character, so the shell split the word and `echo` rejoined it with a space,
and the forged line was rejected for having no separator rather than for being
unreachable. The test would have passed against a sandbox that could write the
channel. The tab is now written as a `printf` escape.

It is gated on `--sandbx-audit-stdin`, the same flag as the write, because the flag
is what says fd 0 is a channel at all. Without it nothing was written there and
there is nothing to protect, so stdin stays inherited — a hand-invoked
`sandbx-helper` running a command that reads its own input keeps working, which an
unconditional `null` quietly took away.

**Defence in depth behind that line.** `decode` accepts only labels in
`Degradation::ALL`, so nothing can name a mechanism sandbx did not define; the
record count is capped at the number of steps that exist; and `encode` strips the
separator characters from a detail so one record cannot forge a second.

## What this is not

Not a boundary in the sense Landlock is. Stage 1 holds the write end on its own
fd 0 for its whole lifetime, and `/proc` is the host's procfs un-remounted —
`confirm_supervisor` depends on reading it. So a policy granting write access over
`/proc` would expose the channel as `/proc/<stage1-pid>/fd/0`, same uid, no ptrace
barrier. The closed label set still bounds the *mechanism*, but `detail` is free
text, so such a policy buys a forged detail on a real mechanism name.

Left as a documented limit rather than closed, and the alternative was weighed:
`nix::unistd::dup2_stdin` could point stage 1's fd 0 at `/dev/null` once the
records are written, which would shut the window. It was not added, because it and
the `Stdio::null()` above would mask each other — with both in place neither one's
removal makes `the_sandboxed_command_cannot_write_the_audit_channel` fail, and the
guard that matters would stop being the guard that is tested. One barrier on the
path untrusted code actually takes, demonstrably load-bearing, beats two that each
look optional. A policy granting `/proc` write hands the command worse than this
anyway; `SECURITY.md` says not to.

## Accepted costs

**The stdin slot is claimed.** A sandboxed command run through `SandboxedCommand`
cannot later be given interactive stdin without moving this channel. Nothing
regresses today: both spawn paths already passed `Stdio::null()`, and the
hand-invoked helper keeps its inherited fd 0 because the `null` is gated on the
flag. If interactive stdin is ever wanted here, the channel needs a different
carrier — most likely a Unix socketpair, which would mean either `unsafe` or a
dependency that encapsulates it.

**`degraded` is timestamped after `spawned`.** sandbx reads the channel only once
the helper has been waited on, so the record lands after the command's own
lifetime even though the degradation preceded it. The trail is complete but not in
causal order. Reading earlier would mean a thread or a poll loop, which is a lot of
machinery for a record emitted at most twice per run — and the fields say what
happened; only the ordering is lossy.

**Not blocking is structural, not lucky.** Nothing drains the pipe while stage 1
writes, so a write that filled the buffer would deadlock the very run it is
reporting on. Two mechanisms, each reporting at most once, with the detail capped
at 256 characters, is three orders of magnitude inside the 64 KiB a Linux pipe
holds — and the cap is unit-tested, so the bound is a property of the format
rather than a hope about the length of errno strings.
