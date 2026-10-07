# The helper's audit channel

Why what the helper learns and sandbx cannot see — a degradation, and a command
that could not be `exec`ed — crosses back as bytes in the **stdin slot** rather
than being logged where it is found (#95, #96).

## The problem

`AuditEvent::Degraded` had two emitters, both in `helper/hardening.rs`:
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
                            │ decode, harden ─┬─ ok
             bad_helper_args\t  ◄─────────────┘ no: refused
                            ├─ drops its handle
                            └─ spawns ──────────► fd 0 ─► CLOEXEC duplicate
                                                 /dev/null ─► fd 0
                                                 restrict, exec ─┬─ ok: closed
reads to EOF                     namespace_setup_failed\t  ◄─────┘ no: refused
  └─ AuditEvent::degraded(..).emit()
  └─ AuditEvent::exited(..) | ::failed(..)
```

`hardening.rs` returns `Vec<(Degradation, String)>` instead of emitting;
`degradation.rs` owns the format and both ends; `exec_sandboxed` writes its
degradations or its one refusal and `exec_inner` writes its one refusal;
`command.rs` reads, decodes and emits.

**Stage 2 reports any refusal, not only a failed `exec`** (#157). It can also refuse
a Landlock ruleset the kernel will not take, a seccomp filter that will not install, a
supervisor already gone, an environment an earlier stage did not narrow — and each of
those exits non-zero, which stage 1 relays on the command's behalf. So the record is
`SandboxError::label` and the trail says `failed reason=<label>`; `exec_failed` is one
member of that set rather than the only thing the channel can carry. The set lives on
`SandboxError`, which owns it because `label` is the exhaustive match a new variant has
to pass through. The claim on fd 0 moves to the top of `exec_inner` for this: a refusal
is only reportable from a point where the channel is already in hand.

**Stage 1 reports its own refusals too** (#160), the same gap one stage up: it exits
non-zero, the parent has only that status, and a malformed argv or a kernel that will
not unshare read as `exited code=1`. It already held the write end for its whole
lifetime, so the write site was the whole of what was missing.

The *region* that reports is what the design is in. `start_inner_stage` holds
everything stage 1 does up to and including the spawn, and only its `Err` is written.
Both edges of that region are load bearing:

- Below it, `child.wait()` failing is not reported. Stage 2 exists by then and may
  have written its own, more specific refusal, and the parent's *last* record wins —
  so a record here would displace it. That is also what keeps the count bounded: each
  stage reports only from above the next stage's existence, so one refusal crosses
  however many stages write, and `RECORD_LIMIT` stays at the steps plus one.
- Above it, `self_exe` is probed in `exec_sandboxed` rather than inside. Its refusal
  is `spawn_failed`, which the channel does not admit; keeping it outside means every
  label the write site can produce is one the reader takes, so the writer and the
  reader agree without a second check at the write. The variant is shared with sandbx
  (`command.rs`), so relabelling it there was not an option.

`inner_stage_failed` is what lets the spawn sit *inside* the region. Stage 1 failing
to start stage 2 would otherwise be `spawn_failed` too, and that label names no single
decider — sandbx returns it about a helper, and stage 1 about its own wait. A channel
record outranks the exit status, so one label for two deciders would let a line claim
a helper that failed to start when one did.

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
pipe up. Stage 1 hands the flag down to stage 2, which reports on the same
channel.

**Stage 2 claiming fd 0 is the security line.** Stage 1 becomes nothing, but
stage 2 becomes the sandboxed command, and an inherited write end would let it
forge records on sandbx's audit trail — or hold the pipe open and leave sandbx
waiting on an EOF that never comes. So before `apply`, where no filter it is
about to install can be what refuses the attempt, stage 2 duplicates fd 0 with
`F_DUPFD_CLOEXEC` (`BorrowedFd::try_clone_to_owned`) and `dup2`s `/dev/null` into
the slot. The command inherits a null stdin; the duplicate the kernel closes on a
successful `exec` is the only live handle on the channel.

Which is what makes the `exec_failed` record true rather than a guess: `exec`
returns only on failure, so a write past it is reachable only in a world where the
command does not exist. Every other refusal is written before the `exec` is even
attempted, so the same holds for it by position. The alternative — a reserved exit
code — would be forgeable by any command that chose to exit with it.

Fail closed: either step failing is a `ProcessHardening` refusal, not a lost
record. Becoming the command with a writable channel on fd 0 is worse than any
record it would have bought.

It is pinned by `the_command_cannot_write_the_audit_channel`, and the
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
`Degradation::ALL` and `HelperRefusal::ALL`, two closed sets kept disjoint by a
test, so nothing can name a mechanism or a reason sandbx did not define; the record
count is capped at the steps that exist plus the one refusal that can cross however
many stages write — see the stage 1 note above; and `encode` strips the separator
characters from a detail so one record cannot forge a second. A refusal carries no
detail at all. The reason reaches the operator on the helper's forwarded stderr, and
the parent lifts it off there into `SandboxError::HelperRefused` for its caller, so
the prose crosses once and is relayed, never re-encoded on the wire (#185).

`HelperRefusal` is a *subset* of what `SandboxError::label` can return, not all of
it, and the five it leaves out are the point: `timeout`, `spawn_failed`,
`path_not_allowed`, `unresolvable` and `not_found` are decisions sandbx and
`FsGuard` make for themselves. A channel record outranks the exit status — and now
the returned `Result` too — so admitting `timeout` would let a forged line claim a
kill that never happened *and* suppress the real outcome, on a trail whose whole
purpose is that `reason="timeout"` can be filtered. What the criterion turns on is
whether the label names one decider, not what failed: `inner_stage_failed` is in and
`spawn_failed` is out although both name a process that would not start.
`SandboxError::refusal` is the one exhaustive place the two sets are mapped, so a
new variant cannot be left out of the set by omission.

## What this is not

Not a boundary in the sense Landlock is. Stage 1 holds the write end on its own
fd 0 for its whole lifetime, and `/proc` is the host's procfs un-remounted —
`confirm_supervisor` depends on reading it. So a policy granting write access over
`/proc` would expose the channel as `/proc/<stage1-pid>/fd/0`, same uid, no ptrace
barrier. The closed label set still bounds the *mechanism*, but `detail` is free
text, so such a policy buys a forged detail on a real mechanism name.

Left as a documented limit rather than closed, and the alternative was weighed:
`nix::unistd::dup2_stdin` could point stage 1's fd 0 at `/dev/null` too, once its
records are written. It was not added, because it would mask the barrier above —
with both in place neither one's removal makes
`the_command_cannot_write_the_audit_channel` fail, and the guard that matters
would stop being the guard that is tested. One barrier on the path untrusted code
actually takes, demonstrably load-bearing, beats two that each look optional.
Stage 2's claim is on that path; stage 1's fd 0 is reachable only through a
`/proc` write grant, which hands the command worse than this anyway, and
`SECURITY.md` says not to.

## Accepted costs

**The stdin slot is claimed.** A sandboxed command run through `SandboxedCommand`
cannot later be given interactive stdin without moving this channel. Nothing
regresses today: the command still gets a null stdin, now from stage 2's `dup2`
rather than from stage 1's `Stdio::null()`, and the hand-invoked helper keeps its
inherited fd 0 because both are gated on the flag. If interactive stdin is ever
wanted here, the channel needs a different carrier — most likely a Unix
socketpair, which would mean either `unsafe` or a dependency that encapsulates it.

**Everything the channel carries is timestamped after `spawned`.** sandbx reads it
only once the helper has been waited on, so a `degraded` record lands after the
command's own lifetime even though the degradation preceded it, and the terminal
record (#96) is emitted from the same read. The trail is complete but not in causal
order. Reading earlier would mean a thread or a poll loop, which is a lot of
machinery for a handful of records per run — and the fields say what happened;
only the ordering is lossy.

**Not blocking is structural, not lucky.** Nothing drains the pipe while the
helper writes, so a write that filled the buffer would deadlock the very run it is
reporting on. Two mechanisms and one detail-free refusal, each reported at most
once, with the detail capped at 256 characters, is two orders of magnitude inside
the 64 KiB a Linux pipe holds — and the cap is unit-tested, so the bound is a
property of the format rather than a hope about the length of errno strings.
Neither widening the refusal's label set nor letting a second stage report widens the
bound: a stage returns at most one error, and reports only from above the next stage's
existence, so at most one refusal record is on the channel whatever refused.
