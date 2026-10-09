# Every mechanism here is the kernel's, not sandbx's

This chapter sits *underneath* the bottom two boxes of **View 1 — three
processes** in [04 — the architecture](04-the-architecture.md): the helper
supervisor, and the helper inner stage that `apply()` confines. Those two boxes
name eight or nine kernel mechanisms in about twenty words of ASCII, and the
chapters after this one assume you know what each of them is.

So this is the one chapter in the set that is almost all kernel and almost no
repository code: one snippet, where the order of three writes *is* the
mechanism. Each section teaches one mechanism from first principles and ends by
naming where in sandbx it is about to show up. If you have called `unshare(2)`
before, skim the last line of each section and move on to
[08 — the two-stage helper](08-the-two-stage-helper.md).

Two conventions for the whole chapter. "The command" means the program sandbx
was asked to run — the thing being confined. "Irreversible" means what it says:
every mechanism below, once installed, cannot be taken off by the process that
installed it, which is the property that lets a process restrict *itself* and
then `exec` something it does not trust.

## Namespaces give one process a different view of a global resource

A namespace wraps some resource the kernel otherwise has exactly one of, so
processes in different namespaces see different instances of it. There are
several types; sandbx uses four.

| namespace | what it virtualises | what a fresh one starts as |
|---|---|---|
| user | uid and gid numbers, and capabilities | no mapping at all, and a full capability set *inside* it |
| pid | process numbers | a new numbering, whose first process is its init |
| mount | the mount table | a copy of the parent's, with its propagation types |
| network | interfaces, routes, ports, abstract unix socket names | one loopback interface, down, and no route |

Three facts about them that the rest of the chapter leans on.

- **`unshare(2)` moves the calling process, with one exception.** Pass
  `CLONE_NEWNET` and the caller lands in the new network namespace immediately.
  Pass `CLONE_NEWPID` and the caller does *not* move: the kernel places the
  caller's future *children* in the new PID namespace, because a running process
  cannot be renumbered out from under code holding its pid. So the only way to
  obtain a process that **is** PID 1 of a new namespace is to unshare in a
  parent and then create a child.
- **A PID namespace's init is special, in two directions.** When it exits, the
  kernel `SIGKILL`s every process still in the namespace — there is no way to be
  a surviving orphan. And a signal sent to it that it has no handler for is
  discarded rather than applying the default action, so `kill -TERM` at the
  command does nothing unless the command installed a handler.
  [`SECURITY.md`](../../SECURITY.md) carries that second half as a non-claim,
  because it is a behaviour change the command can notice.
- **A namespace is inherited across `fork` and across `exec`.** Nothing about an
  `execve` returns a process to the host's view, which is what makes a namespace
  usable as a boundary around a program you are about to become.

### An unprivileged user namespace is the key to the other three

Creating a mount, PID or network namespace needs `CAP_SYS_ADMIN`. An ordinary
user does not have it, which for years meant namespaces were a root-only tool.

What changed is that `CLONE_NEWUSER` may be requested by anyone, and a process
that enters a user namespace it just created holds a **full capability set
within that namespace**. Request `CLONE_NEWUSER` in the *same* `unshare` call as
the others and the kernel grants the new credentials before it checks the
permission for the rest — so one call makes all four namespaces unprivileged,
while two calls would not.

That capability set is confined to the new namespace. It is `CAP_SYS_ADMIN` over
*these* mounts and *this* network stack, and nothing at all over the host's.
Which is why this is not a privilege escalation and also why hardened
distributions restrict it anyway: a full capability set inside a namespace is a
large amount of kernel surface reachable from an unprivileged account, and a bug
in any of it is a bug reachable by anyone. Both
`kernel.unprivileged_userns_clone` and AppArmor's
`kernel.apparmor_restrict_unprivileged_userns` exist to turn it off or to strip
capabilities back out of it, and a sandbox built on this has to have an answer
for a host where that has been done.

**In sandbx:** `isolate` in
[`hardening.rs`](../../crates/sandbx-core/src/helper/hardening.rs) makes exactly
one `unshare` call, so there is no window holding some of the isolation and not
the rest. The user and PID namespaces are unconditional; the network namespace
is dropped when the policy grants network at all, and the mount namespace is
added only when the policy has mounts to put in it — an empty one confines
nothing, and unsharing it regardless would make every run, mounts or not, depend
on a kernel that lets an unprivileged process have one. A refused `unshare` is a
refused run — see the rows in
[guide-sandboxing.md](../guide-sandboxing.md#namespaces-and-process-state).

## The identity maps, and why `setgroups` must be denied first

A fresh user namespace has no uid mapping, so the kernel has no number in it for
the process that created it. `getuid()` then reads back as the *overflow uid* —
`nobody`, conventionally 65534 — even though the process's on-host identity has
not changed at all and files it writes are still owned by the real user.
Programs that branch on their own uid see a value that does not match reality.

The fix is to write a mapping. `/proc/self/uid_map` and `/proc/self/gid_map`
take lines of three numbers — the id inside the namespace, the id outside it,
and how many consecutive ids the line covers — and an unprivileged writer may
establish exactly one line, mapping its own id. Writing `1000 1000 1` maps the
real uid to itself: it grants nothing, since the process was already acting as
that uid, and it makes `getuid()` truthful again.

One line, and your own id, is not an arbitrary quota. A wider map needs
`CAP_SETUID` — `CAP_SETGID` for the gid map — held over the **parent**
namespace, and the full capability set the creator holds *inside* the new one
is no help, because that is not where the kernel checks. Which is why the tool
that hands out a range of subordinate ids, `newuidmap(1)`, is a set-user-ID
binary: the privilege has to come from outside the namespace being mapped.
sandbx has no such helper, so one id mapped to itself is all it can write.

But `/proc/self/gid_map` is refused for an unprivileged writer until
`/proc/self/setgroups` has been written the string `deny`, and that ordering
closes a specific attack rather than being a formality.

`setgroups(2)` sets a process's supplementary groups, and inside a user
namespace you created you hold `CAP_SETGID` and so may call it — including to
**drop** a group. Dropping a group normally takes privilege away. It does not
when a file's mode gives the group *fewer* permissions than other: mode `0604`
means "owner: read-write, group: nothing, other: read", and a member of that
group is denied a file everyone else may read. Shedding the membership turns you
into "other" and the file opens. The user namespace granted no new access to the
file; it merely handed over the ability to stop being the group that was being
denied.

So the kernel forces the order. Writing `deny` to `setgroups` permanently
disables `setgroups(2)` in that namespace, and only then may an unprivileged
process write `gid_map`; once `gid_map` is written, `deny` can no longer be
written at all. One order works and the other cannot be recovered from.

**In sandbx:** `map_identity_into_userns_with` in `hardening.rs` writes the
three paths in that order, and the order is a literal:

```rust
let maps = [
    ("/proc/self/setgroups", "deny".to_string()),
    ("/proc/self/gid_map", format!("{gid} {gid} 1")),
    ("/proc/self/uid_map", format!("{uid} {uid} 1")),
];
```

The unit test beside it, `the_identity_map_is_written_in_kernel_order`, asserts
the sequence rather than the outcome — the kernel's refusal is the thing being
avoided, so the order is what has to be pinned. The whole step is best-effort: a
host that creates the namespace and then denies the map leaves the process
reading back as `nobody`, which is if anything more restrictive, so the run
continues with a `degraded` record rather than refusing.

## seccomp-BPF is a program over the syscall's registers

A seccomp filter is a classic-BPF program the kernel runs on *entry to every
syscall*, before the syscall's own code. Its input is a fixed structure,
`seccomp_data`:

```
struct seccomp_data {
    int   nr;                 the syscall number
    __u32 arch;               AUDIT_ARCH_X86_64, AUDIT_ARCH_AARCH64, …
    __u64 instruction_pointer;
    __u64 args[6];            the six argument registers, as integers
};
```

Its output is a verdict: allow, return an errno, kill the process, trap, notify
a supervisor.

Classic BPF is a small register machine, and its shape is worth knowing because
[10 — seccomp](10-seccomp.md) reads one of these programs instruction by
instruction. A program is a short list of operations over a single accumulator:
load a word at a byte offset into the struct above, mask it, compare it against
a constant, jump — and the verdict is whatever a closing `ret` leaves behind.
Jump offsets are unsigned and counted from the *following* instruction, so a
program only ever goes forward. There are no loops, which is what lets the
kernel decide before accepting a filter that the thing terminates, and so what
makes running it on every syscall affordable.

Four properties make it usable as a boundary:

- **Installing one needs either `CAP_SYS_ADMIN` or the `no_new_privs` bit**, so
  an unprivileged process can have a filter by setting that bit first. This is
  the ordering constraint that shows up at the top of `apply`.
- **Filters stack and the most severe verdict wins.** A process may install
  several; the kernel runs all of them and takes the worst answer, so a later
  filter cannot loosen an earlier one and install order carries no meaning.
- **A filter cannot be removed**, and it is inherited across `fork` and across
  `exec`. It attaches to the *calling thread*, though: siblings already running
  are covered only if the installer asks, with `SECCOMP_FILTER_FLAG_TSYNC`. A
  process that has just `exec`ed has one thread, so the distinction disappears
  there — which is the shape a filter gets installed in.
- **It is per-architecture.** Syscall numbers mean different things on different
  ABIs, so a filter that does not gate on `arch` is a filter that can be walked
  past by issuing the same number through another one.

### What it structurally cannot see

`args[6]` are the *register values*. A pointer argument is therefore a number,
and the kernel will not dereference it on the filter's behalf. That is a design
decision, not an omission: memory is shared and writable, so anything the filter
read out of it could be rewritten by another thread between the check and the
syscall's own read of the same bytes. A filter that followed pointers would be a
TOCTOU generator.

Everything behind a pointer is consequently invisible, and three limits in
`SECURITY.md` are that one fact wearing different hats. `connect`'s destination
sits in a `sockaddr` behind a pointer, so seccomp can police a socket's family,
type and protocol but never its address — which is why a port allowlist is not a
destination allowlist. A unix socket's path is in the same structure, so unix
sockets are all-or-nothing. And a filename is always behind a pointer, which is
the whole reason a second mechanism — Landlock — has to exist for paths.

The sharpest case is a pair of syscalls that do the same job with the arguments
in different places. `clone(2)` takes its flags as an integer argument, so a
filter can compare them and refuse a call carrying `CLONE_NEWUSER` or
`CLONE_NEWPID`. `clone3(2)` takes a pointer to a `struct clone_args` whose
`flags` field lives in memory, so no filter can tell a thread creation from a
namespace creation. There is no narrow rule available: the call has to be
refused outright.

**In sandbx:** `deny_dangerous_syscalls` in
[`seccomp.rs`](../../crates/sandbx-core/src/helper/seccomp.rs) installs a
denylist, plus conditional rules for `socket`, `setsockopt` and the send
syscalls, as a stack of filters — three on x86\_64, two elsewhere — because a
seccompiler filter carries a single match action and some rules need a different
one. Each goes in through seccompiler's `apply_filter` — the calling-thread
call, not the all-threads one — which is sound only because the stage that
installs them is a fresh `exec` and so has a single thread; the command inherits
the filters from there. `clone3` answers `ENOSYS` rather than `EPERM`, and
`clone3_filter` says why in a comment: glibc calls it from `pthread_create` and
falls back to `clone` only on `ENOSYS`, so the polite errno is what routes
threaded programs onto the filtered `clone` instead of breaking them. The list,
the filters and their actions are in
[guide-sandboxing.md](../guide-sandboxing.md#syscall-denylist).

## Landlock is a path-based LSM with a versioned ABI

Landlock is a security module a process applies **to itself**, with no privilege
and no configuration file. The shape of the API is three steps:

1. create a ruleset, declaring the set of access types it will *handle*;
2. add rules to it — each one a descriptor for a directory or file, plus the
   rights permitted beneath it;
3. call `landlock_restrict_self`, after which the ruleset applies to this thread
   and to everything it later spawns or `exec`s, irreversibly.

Rights are per *access type*, and there are many: reading a file, writing a
file, executing one, creating or removing entries of each kind,
`rename`/hard-link across directories, truncating, `ioctl` on a device, binding
and connecting TCP. A rule attaches to the **inode** the descriptor holds, not
to the name it was opened by, so renaming the directory afterwards moves the
name and not the rule.

Two facts dominate everything sandbx does with it.

- **An access type not in the handled set is unrestricted everywhere.** Not
  denied, not partially restricted: untouched, as though no ruleset existed. A
  ruleset is a sentence of the form "I police these verbs; grant me these
  nouns", and any verb left out of the first clause is free. Forgetting to
  handle an access type is therefore not a tighter sandbox with a gap, it is a
  whole category with no sandbox at all.
- **The ABI is versioned, and the version is the kernel's.** Each level adds
  access types. Ask for rights a kernel does not know and you choose between two
  behaviours: *best-effort*, where the kernel silently drops what it does not
  understand — which, by the previous point, leaves those types unrestricted —
  or *hard requirement*, where the whole call is refused. Best-effort is the
  trap, because it succeeds.

A third fact is worth knowing early because it closes a question people reach
for: Landlock has no right covering path *resolution*. A confined process can
still `stat` and test the existence of any path it can name. Landlock bounds
what you may do to a file, never whether you may learn that it is there.

**In sandbx:** three constants in
[`ruleset/compat.rs`](../../crates/sandbx-core/src/helper/ruleset/compat.rs)
hold the whole version story — `BASELINE_ABI` is the floor the build refuses to
run below, `LATEST_ABI` the newest level it knows about, and `NEGOTIABLE_ABI`
the ladder between them, written out newest-first because the ABI type is a
closed enum with no arithmetic. `negotiated_abi_from` walks that ladder under
`HardRequirement` and settles on the first rung the kernel accepts in full; the
*only* error it treats as a verdict about the ABI is the one `handle_access`
returns, and anything else is a refusal, because stepping down on an unrelated
error would leave every right above the chosen rung unhandled. Below the floor
the run is refused rather than downgraded. The figures are in
[`SECURITY.md`](../../SECURITY.md) and nowhere else in prose — a test named
`every_prose_copy_of_the_floor_is_current` pins each copy, and its comment says
each new one is another way for an edit to break the build.

- **Worth questioning:** negotiating *up* means the same policy enforces a
  different handled set on two different kernels, and nothing tells the operator
  which rung was taken. A newer kernel handles more access types, so a command
  that worked on one host can be denied on another for a right the first kernel
  never policed, and the only evidence is the command's own `EACCES`. The
  negotiation happens in helper stage 2, which has no `tracing` subscriber by
  design, so the audit trail's `spawned` record — built in the harness from
  policy counts — cannot carry it.
  [decision-helper-audit-channel.md](../decision-helper-audit-channel.md) is the
  record to argue with: it chose a one-way channel carrying mechanism names from
  a *closed set* rather than arbitrary bytes, precisely so the command cannot
  forge a record, and a negotiated rung is a number rather than a label. That
  reasoning is about forgeability, though, and a rung is not attacker-chosen —
  it is the kernel's answer to a probe. A fixed-vocabulary record saying which
  rung was taken looks compatible with everything that record decided.

## `O_PATH` lets you name a file without opening it

`open(path, O_PATH)` returns a descriptor that refers to a *location in the
filesystem tree* rather than to an open file. You cannot read or write through
it. What you can do is use it where the kernel wants a reference to an object:
`fstat` it, pass it as the `dirfd` of an `*at` call, or hand it to Landlock as
the directory a rule is attached beneath.

The point is the permission it does *not* need. An `O_PATH` open requires only
execute (search) permission on the directories leading to the file, never read
permission on the file itself. So it is a *lookup*, not an access — exactly what
you want when the question is "which object does this name lead to right now?"
and the answer is supposed to be decided before any access happens.

Its natural partner is `/proc/self/fd`. Procfs gives every open descriptor a
magic symlink there, and `readlink` on it returns the path the kernel currently
associates with that object. Two different uses come out of that:

- **Reading back what you actually opened.** A path is resolved component by
  component, and `O_PATH` without `O_NOFOLLOW` follows every symlink in it. The
  readback is how you discover that the name you asked for led somewhere else —
  and if the file has been unlinked, the kernel appends the literal
  `" (deleted)"`, so an unlinked object is visibly not the thing you named.
- **Using a descriptor as a name.** `/proc/self/fd/N` is a path, so any syscall
  that takes a path can be handed an object you already hold open. That is how
  you can hash a file and then `execve` *that* file rather than re-resolving its
  name and hoping.

One permission detail that both uses depend on: a process may always read its
own `/proc/self/fd`. The check that guards another process's descriptor
directory is a ptrace-access check, and procfs exempts a reader in the same
thread group — the comment on `reads_back` in
[`opened.rs`](../../crates/sandbx-core/src/helper/ruleset/opened.rs) names the
kernel function it is relying on, and adds the second reason it holds here: an
`execve` resets the dumpable flag that check consults anyway.

**In sandbx:** `open_grant` in `opened.rs` opens each granted path `O_PATH`,
reads it back through `/proc/self/fd`, and refuses the whole run if the spelling
differs from the grant — then `fstat`s the same descriptor and refuses again if
the `(dev, ino)` differs from the pair the harness vetted (#205, #212). Two
questions, because a symlink redirected between the two processes changes the
spelling and a `rename(2)` does not. `VettedPath::confirm` asks the second
question again, in-process, for the six tools that never spawn anything.

## A bind mount is a second name, and read-only takes two calls

`mount(2)` with `MS_BIND` attaches an existing file or subtree at a second
location. There is one inode with two names; a write through either is visible
through both. The target must already exist, because the mount is attached over
an existing directory entry — and `mount(2)` *resolves* the target, so binding
over a symlink lands on whatever the link points at and leaves the link itself
an ordinary entry.

The quirk worth memorising is that `MS_BIND | MS_RDONLY` does not give you a
read-only bind. On the bind call the kernel takes the new mount's attributes
from the *source* mount and ignores the flags you passed alongside `MS_BIND`.
Making it read-only is a **second** call over the same target, with
`MS_BIND | MS_REMOUNT | MS_RDONLY`, which changes that mount's own flags. Miss
it and you have a writable mount that looks from the code like a read-only one.

The other half of mount semantics is *propagation*. A mount namespace starts as
a copy of its parent's table, and each mount in it carries a propagation type
that decides whether later mount events cross between them. The default on most
distributions is `shared`, which propagates in both directions. Unsharing the
mount namespace in the same call as a *user* namespace turns a shared mount into
a **slave** in the copy instead — and a slave still receives its master's
events. Either way a fresh mount namespace is not isolated from mounts the host
makes afterwards until you say so, with `MS_REC | MS_PRIVATE` on `/`; `MS_REC`
because the type is per mount and `/etc` may be a mount of its own. The
slave-in-the-copy rule is the comment on `detach_mount_propagation`, which is
the source for this paragraph; the resolver row of
[guide-sandboxing.md](../guide-sandboxing.md#namespaces-and-process-state)
states it too.

**In sandbx:**
[`helper/resolver.rs`](../../crates/sandbx-core/src/helper/resolver.rs) is one
ordered mount sequence, and the module doc says the order is the whole of it.
`detach_mount_propagation` runs before any bind of sandbx's own, `install` makes
both calls per file, and `remove_source` detaches the tmpfs the bodies were
written to with `MNT_DETACH` rather than unlinking them — the comment on
`source_dir` explains that an unlinked bind source would make every grant on one
of those paths read back with `" (deleted)"` and refuse the run. What the three
files buy is in the *name resolution* row of [`SECURITY.md`](../../SECURITY.md);
`mount_setattr(2)`, which could clear `MS_RDONLY` on a mount already there, is
on the syscall denylist for that reason.

## `no_new_privs` is one bit, and it buys two things

`prctl(PR_SET_NO_NEW_PRIVS, 1)` sets a per-process flag that cannot be cleared,
is inherited by children, and survives `execve`. Its stated meaning is that no
`execve` from here on may grant this process a privilege it does not already
have: set-user-ID and set-group-ID bits are ignored, file capabilities confer
nothing, and an LSM transition that would raise privilege is refused.

The second thing it buys is the one that matters for the shape of the code:
**installing a seccomp filter requires either `CAP_SYS_ADMIN` or
`no_new_privs`.** The reason is the interaction above. A filter is inherited
across `execve`, so without the bit an unprivileged process could install a
filter designed to make a set-user-ID program misbehave — have a
security-relevant syscall return a lie the program does not check — and then
`exec` it. Forbidding the privilege gain removes the target, and so the bit is
the unprivileged route to having a filter at all.

`landlock_restrict_self` carries the same precondition — `CAP_SYS_ADMIN` or the
bit — for the same reason, a ruleset being inherited across `execve` too. So the
second thing covers both self-applied mechanisms: one `prctl` is what an
unprivileged process has to spend before either will install.

**In sandbx:** `set_no_new_privs` is called in the supervisor *and* again as the
first statement of `apply`. The second call is a no-op, and the comment in
`prepare_supervisor` says why it is there anyway: the stage that installs the
filter must not depend on a caller having set the bit for it. Neither install
relies on those two calls: `seccompiler::apply_filter` opens with the same
`prctl` and returns `Error::Prctl` if it fails, and the `landlock` crate sets
the bit inside `restrict_self` and defaults to doing so. What sandbx's own call
buys is the *refusal* — a kernel that will not set the bit is reported once,
under one named error, ahead of either install rather than as whichever of the
two happened to run first — which is why it sits before
`deny_dangerous_syscalls` in `apply` and not anywhere later.

## Five capability sets, and what dropping each one means

Capabilities split root's power into pieces — `CAP_SYS_ADMIN`, `CAP_NET_RAW`,
`CAP_SETPCAP`, around forty of them — and the kernel checks a specific one
rather than "am I uid 0". Each thread carries five sets, and they are not five
copies of the same idea: four of them exist to answer "what happens across the
next `execve`", which is exactly the question a sandbox cares about.

| set | what the kernel does with it | what an empty one means |
|---|---|---|
| effective | the set every capability check consults | no privileged operation succeeds now |
| permitted | the ceiling: a capability may be raised into effective only from here | nothing can be raised back |
| inheritable | combines with the *file's* inheritable set to form the new permitted set after `execve` | that route across `execve` is closed |
| ambient | the set that does survive `execve` of an ordinary binary, landing in permitted and effective | the other route across `execve` is closed |
| bounding | a mask on what can ever enter inheritable, or be gained from a file's permitted set | no file capability can reintroduce one |

Two corollaries sandbx depends on. Ambient is masked by the other two — a
capability stays in ambient only while it is in both permitted and inheritable,
so emptying those empties ambient as well. And all five sets, like the
namespaces, are inherited across `fork` and across `exec`, so a process that
empties them before becoming the command has emptied them *for* the command.

Dropping the bounding set is the one that needs a privilege of its own:
`PR_CAPBSET_DROP` requires `CAP_SETPCAP` **in the effective set**. So the order
is forced — bounding first, effective afterwards — and an LSM that strips
`CAP_SETPCAP` out of a freshly created user namespace makes the drop fail while
the `unshare` succeeds.

**In sandbx:** `harden_process_state` drops bounding, then effective, permitted,
inheritable and ambient, then sets `RLIMIT_CORE` to zero. The drops happen
*after* the `unshare`, because entering a fresh user namespace grants the full
set within it and dropping earlier would be undone. The bounding set is
best-effort and the other four are hard, and the long comment on
`harden_process_state` is the argument for that asymmetry: with the four empty
and `no_new_privs` set, the kernel caps an `execve`d binary's permitted set at
the old one and refuses to raise inheritable or ambient, so the bounding bit
cannot be spent — and refusing would take the sandbox away on whole classes of
host for nothing. [`SECURITY.md`](../../SECURITY.md) states it as "do not rely
on `CapBnd` being empty; do rely on the other four". `RLIMIT_CORE` is in the
same function for a related reason: `PR_SET_DUMPABLE` is reset to dumpable by
every `execve` of an ordinary binary, so only the rlimit reaches the command.

## `PR_SET_PDEATHSIG`, and the two cases that clear it

`prctl(PR_SET_PDEATHSIG, sig)` asks the kernel to send `sig` to *this* process
when its parent dies. The kernel delivers it, so it needs no cooperation from
the parent and no supervisor watching — which is what makes it usable for "do
not outlive whoever started me".

Two cases clear the setting, and both shape how it can be used.

- **The child of a `fork` does not inherit it.** The setting protects exactly
  one process and never a subtree, so it cannot be the mechanism that bounds a
  command's descendants. Something else has to do that.
- **A *secure* `execve` clears it** — a set-user-ID or set-group-ID target, or
  one carrying file capabilities. Keeping it would let an unprivileged parent
  arrange for an arbitrary signal to arrive at a privileged image at a moment of
  its choosing. An ordinary `execve` preserves it, which is what lets a process
  arm the signal and then become the command.

And one case where arming it achieves nothing at all: if the parent is *already*
dead when the `prctl` runs, there is no future death to report and the signal
never fires. Arming is therefore not sufficient on its own — after arming you
have to establish that the parent you meant is still there, and the check and
the arming cannot be in the other order.

And a last piece of vocabulary, because the kernel is more specific than the
word "parent" suggests: the signal is tied to the parent **thread**, the one
that created this process, and fires when *that* thread exits even if its
process goes on running. A multithreaded parent that spawns from a worker
cannot use the setting to mean "while my process lives". A single-threaded one
makes the two readings the same thing.

Checking is harder than it looks from inside a new PID namespace. `getppid()` is
translated into the caller's own namespace, and a process whose parent lives
*outside* that namespace has no number to be told: the kernel reports 0. The
parent is still nameable in *host* numbering, through field 4 of
`/proc/self/stat`, as long as `/proc` is the host's procfs.

**In sandbx:** `bind_lifetime_to_supervisor` then `confirm_supervisor`, in that
order, in the inner stage — the subject of
[08](08-the-two-stage-helper.md#arm-then-confirm). The descendant bound that
`pdeathsig` cannot provide comes from the PID namespace instead: the inner stage
is its init, so the kernel kills everything left in the namespace when it dies.
[guide-process-lifetime.md](../guide-process-lifetime.md) has the kill chain the
two mechanisms form, and `SECURITY.md` names the one shape that survives both —
a command whose `pdeathsig` a secure `exec` cleared *and* which called `setsid`
to leave the process group — along with the reason it is unreaped rather than
unrestricted.

## You should now be able to explain

- Why `unshare(CLONE_NEWPID)` cannot make the caller PID 1, and what that forces
  about the number of processes.
- What an unprivileged user namespace grants, where that grant applies, and why
  requesting it in the same call as the other namespaces is the trick that makes
  them unprivileged.
- The attack that writing `deny` to `setgroups` before `gid_map` closes, in
  terms of a file mode where group has less access than other.
- Why an unprivileged process may map one id to itself and no more, and where
  the privilege for a wider map would have to come from.
- What a classic-BPF program is made of, and why one that cannot loop is cheap
  enough to run on entry to every syscall.
- Why a seccomp filter can police `clone`'s flags but not `clone3`'s, and the
  general rule about pointers that both follow from.
- Why installing a filter on the calling thread is the whole process in a
  process that has one thread, and what the other case needs.
- Why an access type missing from a Landlock ruleset's handled set is worse than
  a denied one, and what "hard requirement" buys over best-effort.
- What `O_PATH` gives you that an ordinary open does not, and the two different
  jobs `/proc/self/fd/N` does.
- Why making a bind mount read-only takes a second `mount(2)` call, and why a
  fresh mount namespace still sees the host's later mounts until something says
  otherwise.
- Why an unprivileged process must set `no_new_privs` before it can install a
  seccomp filter, and why Landlock asks for the same bit.
- Which of the five capability sets answer a question about `execve`, and why
  the bounding set has to be dropped before the effective one.
- The two cases that clear a parent death signal, the third case where arming it
  does nothing, which thread the kernel means by "parent", and what covers a
  command's descendants instead.

## Next

[08 — the two-stage helper](08-the-two-stage-helper.md), where every primitive
above appears again as a line of this repo's own code, in a sequence whose
forced orders are fewer than they look and worth separating from the chosen
ones.
