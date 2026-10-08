# A grant becomes a Landlock rule, or the run is refused

One box of [04 — the architecture](04-the-architecture.md), zoomed all the way
in: the `bash` tool's `SandboxedCommand`, inside stage 2, where `apply()` turns
a `SandboxPolicy` into something the kernel holds. Six of the seven built-in
tools never arrive here at all — they end at `FsGuard`.

This chapter is the Landlock half of that box. How an ABI gets chosen, what a
grant confers once one is, and the two questions asked about every granted path
before the kernel is told about it. `apply`'s own ordering is not re-derived
here. [guide-sandboxing.md](../guide-sandboxing.md) is the authority for the
subsystem and [`SECURITY.md`](../../SECURITY.md) is the normative claim; both
carry the figures this chapter deliberately does not.

[`helper/ruleset/`](../../crates/sandbx-core/src/helper/ruleset/) is four files
with one job each, and its module doc states the division: `compat` is what
*this kernel* will enforce, `rights` is what the *policy* maps to at a given
ABI, `opened` is which directory a grant turns out to name, and `mod.rs` is
where the first two meet — because the rights a grant confers depend on which
ABI was negotiated. Nothing in any of the four restricts the calling process.

## The ladder is walked newest first and stops at the floor

[`compat.rs`](../../crates/sandbx-core/src/helper/ruleset/compat.rs) holds three
constants and nothing else decides which ABI a run gets. `LATEST_ABI` is the
top, `BASELINE_ABI` is the floor, and `NEGOTIABLE_ABI` is the rungs between
them, written out newest first. Written out rather than generated because
`landlock::ABI` is a closed enum with no iterator and no arithmetic — and a
literal ladder is the thing an ABI bump is forced to edit, beside the two
constants that bound it.

This chapter names those constants wherever a number would go.
[`SECURITY.md`](../../SECURITY.md) and
[guide-sandboxing.md](../guide-sandboxing.md) hold the floor and the kernel
release it shipped in, and the test `every_prose_copy_of_the_floor_is_current`
names every file allowed to restate them — a list these chapters stay off, on
the reasoning in [the index](README.md).

**Why there is a floor rather than a preference** is the one thing to carry out
of this section, and it is a property of Landlock rather than a policy choice:
an access type that is *not* in the handled set is unrestricted **everywhere**.
Not loosely held — not held at all. So an older kernel does not give a weaker
sandbox, it gives a sandbox with whole categories missing, and the sensible
response is to refuse.
[01 — what sandbx is](01-what-sandbx-is.md#what-the-kernel-has-to-provide)
quotes the comment on `BASELINE_ABI` that says so.

That is also why `handled_access` is `AccessFs::from_all(abi)` and not an
enumeration of the rights sandbx knows about. A right a future ABI adds lands
in the handled set automatically, and is therefore *denied* unless some axis
confers it. An enumeration would leave it unhandled, which means unrestricted,
until somebody noticed.

### The probe asks the question the real call will ask

`negotiated_abi` calls `negotiated_abi_from(kernel_probe)`, which walks
`NEGOTIABLE_ABI` in order and settles on the first rung the probe accepts.

`kernel_probe` builds a ruleset at `CompatLevel::HardRequirement` — "give me all
of this or fail" rather than Landlock's default best-effort — hands it
`handled_access(abi)` and `handled_net_access(abi)`, and calls `create()`.
Creating a ruleset is not applying one: nothing is restricted until `apply`
reaches `restrict_self`, so the whole ladder can be walked in a single process
with no re-exec and no child. And the probe and `apply` read their handled set
from the same two functions, one spelling each, so the probe cannot settle on a
rung by answering a question `apply` never asks.

| the probe answers | `negotiated_abi_from` does |
|---|---|
| `Ok(())` | settles on this rung and returns it |
| `Err(RulesetError::HandleAccesses(_))` | steps down exactly one rung |
| any other `Err` | refuses, carrying the kernel's own reason |
| nothing left below the floor | refuses as `Unsupported`, naming the floor |

**Only one error is an ABI verdict.** Under `HardRequirement`, `handle_access`
is the call that refuses a partly-supported set and names the rights this kernel
lacks, so `HandleAccesses` is the one answer that means "not this rung, try a
lower one". Every other error says nothing about which ABI the kernel has, and
stepping down on it would pick a rung for the wrong reason — leaving every right
above that rung unhandled, which is to say unrestricted everywhere. Landlock
being absent altogether still arrives as `HandleAccesses`, so it walks the whole
ladder and falls off the end.

The two refusals are deliberately different errors. `Unsupported` names the
floor; `Landlock` carries whatever the kernel said. Collapsing them would report
the floor as the cause of a failure that had nothing to do with it. The pair is
pinned by `a_non_verdict_error_refuses_without_stepping_down` and
`a_kernel_below_the_baseline_is_unsupported`, both of which run on a host with
no Landlock at all, because `negotiated_abi_from` takes the probe as a
parameter.

### The network axis steps a rung the policy never asked for

`kernel_probe` hard-requires **both** axes, and is policy-independent in both.
So the one access category that can walk the ladder down on its own is the
network one: an unsupported `AccessNet` right comes back as the same
`HandleAccesses`, and a kernel missing it drops the run to a lower rung even
when the policy grants no network at all.

That is the point rather than a side effect, and the doc on `kernel_probe` says
why: a probe that skipped the network axis could settle on a rung whose network
rights `apply` then hard-requires — and by then the negotiation is over, so
there is no step-down left and the run is simply refused. Paying a rung in the
probe keeps the negotiated ABI a property of the kernel rather than of the run.
Both of `BindTcp | ConnectTcp` arrived below the floor, so the network set is
never empty here.

Whether the axis is handed over *at all* is a separate decision, made in
[`rights.rs`](../../crates/sandbx-core/src/helper/ruleset/rights.rs)'s
`net_rules`, and it is the one place in the ruleset where "nothing" and "an
empty list" differ: handling `AccessNet` with zero `NetPort` rules denies every
TCP port, while leaving the axis unhandled leaves TCP unrestricted. So a denied
policy and a bare `--allow-network` both map to `RequestedNet::Unhandled` — the
first confined by `CLONE_NEWNET` instead, the second having asked for
unrestricted egress — and only a port list maps to `Ports`. The enum exists so
that rights and ports cannot be passed separately, an empty
`BitFlags<AccessNet>` being exactly the fail-open spelling of `Unhandled`.

## Partial enforcement is a hole, not a smaller sandbox

`restrict_self` hands back a `RulesetStatus`, and `enforcement_verdict` is total
over it:

```rust
match status {
    RulesetStatus::FullyEnforced => Ok(()),
    RulesetStatus::PartiallyEnforced => Err(SandboxError::Unsupported {
        detail: "kernel enforced only part of the ruleset; some access type \
                 is unrestricted, so the sandbox would not hold",
    }),
    RulesetStatus::NotEnforced => Err(SandboxError::Unsupported {
        detail: "kernel accepted the ruleset but enforced none of it",
    }),
}
```

The detail string says the reasoning. `PartiallyEnforced` means Landlock left
some requested access type unhandled, and an unhandled access type is
unrestricted everywhere — so "partly applied" is not "most of the policy
applied", it is the whole policy plus one unguarded category. A sandbox with a
category missing is not a smaller sandbox.

Two things make that verdict possible rather than theatrical.

- **Negotiation asked for nothing the kernel had not already confirmed,** so
  full enforcement is the normal outcome and partial enforcement is an anomaly
  worth refusing. Asking for `LATEST_ABI` best-effort instead would have the
  kernel silently drop what it lacks, leaving every older kernel
  `PartiallyEnforced` — at which point the only way to run anything is to accept
  the status, and the check is gone.
- **The match is total rather than a comparison against one variant.**
  `status == NotEnforced` lets `PartiallyEnforced` through, and a variant a
  future `landlock` release adds would land in whichever arm was written as the
  accepting one. This is 04's recurring trick again: a closed enum plus an
  exhaustive match is a compile-time gate.

The asymmetry behind all of this is on `Requested` in
[`mod.rs`](../../crates/sandbx-core/src/helper/ruleset/mod.rs), and it is worth
reading once. A rule carrying rights *above* the handled set is caught:
`PathBeneath` narrows it, the ruleset comes back `PartiallyEnforced`, and the
verdict refuses. A rule *below* it is not caught by anything — every right the
newer ABI added is simply not granted, the policy promises more than the kernel
was told to allow, and no kernel-free test can see it. Which is why `handled`,
`rules` and `net` are computed together from one ABI in `requested_at`, and why
`Requested` is destructured by every consumer rather than read field by field: a
field added later fails to compile at `apply` instead of being quietly ignored.

## What a grant confers, as bit arithmetic

`landlock::AccessFs` is a `BitFlags` set, so the familiar operators do set
algebra: `!` is complement, `&` is intersection, `|=` is union-assign. The
kernel ships three named sets per ABI — `from_all`, `from_read`, `from_file` —
and `rights_for` builds each axis's rights out of them by **subtraction** rather
than by enumeration:

```rust
let read_rights = AccessFs::from_read(abi) & !AccessFs::Execute;
let write_rights = AccessFs::from_all(abi) & !AccessFs::from_read(abi);
```

Both subtractions are load-bearing, and for different reasons.

- **Read is `from_read` minus `Execute`,** because the kernel's own read set
  bundles `Execute` in with `ReadFile` and `ReadDir`, and no axis but
  `ReadExecute` says *run*. Taking `from_read` as it comes would make
  `--allow-read` an execute grant.
- **Write is `from_all` minus the whole read set,** not minus `Execute` alone.
  `from_all` contains `ReadFile` and `ReadDir` too, so subtracting only
  `Execute` would confer read at the kernel while `FsGuard` refused it in
  process — and the write-only drop directory the policy advertises would be
  readable.
- **Subtraction rather than a list is what makes a future ABI fail safe.** A
  right added to `from_all` next year is denied by `allow_read` automatically,
  rather than being permitted until somebody notices it is not in the
  enumeration.

Then the axis table decides which of the three primitives apply:

```rust
    let mut rights = landlock::BitFlags::EMPTY;

    if read {
        rights |= read_rights;
    }
    if write {
        rights |= write_rights;
    }
    if execute {
        rights |= AccessFs::Execute;
    }
```

`read`, `write` and `execute` there are the destructured fields of
`axis.grants()` — booleans, not Landlock bits, so the policy says what it means
in terms no enforcement layer owns. `Axis::Read` is `(true, false, false)`,
`Axis::Write` is `(false, true, false)`, and `Axis::ReadExecute` is
`(true, false, true)`: **the one grant that confers both**, and the only one
that confers execute at all. It exists because a program needs execute on the
binary *and* read on the libraries its loader pulls in.

Reading the arithmetic back, `read_rights | AccessFs::Execute` is exactly
`from_read(abi)` — the `Execute` bit subtracted on the way in comes back for the
one axis entitled to it, which is why execute is "the single bit, hence addable
on top of read without widening anything else".
[decision-axis-table.md](../decision-axis-table.md) states the three identities
together and records what happened when a row was flipped to see which tests
noticed.

Driving the whole thing off `axis.grants()` is what makes the table a table: a
fourth axis needs no edit in `rights_for`, where a literal list of
`(axis, rights)` pairs would still compile with an axis missing from it and that
grant silently absent. The unit tests close the loop from the other end —
`a_read_grant_never_carries_execute`, `only_the_execute_axis_carries_execute`,
`a_write_grant_carries_neither_read_nor_execute`, and
`no_combination_of_grants_confers_execute`, which walks the powerset of
`Axis::ALL` so that no *union* of grants can reach execute either.

One last narrowing, after the union:

```rust
    if target_is_dir {
        rights
    } else {
        rights & AccessFs::from_file(abi)
    }
```

Directory-only rights (`ReadDir`, `MakeDir`, `Refer`) are invalid on a regular
file, so a policy naming one gets its rights intersected with what the target
can carry. Dropping that intersection would not degrade quietly: `PathBeneath`
stats the descriptor, strips the directory-only bits itself and reports the
result as partial, which under the `HardRequirement` `apply` sets fails
`add_rule` — so `--allow-read ./config.toml` would refuse the run. The real
mapping is therefore `axis × target_is_dir × abi`, with the ABI a negotiated
parameter rather than something ambient.

- **Worth questioning:** the write-minus-read subtraction exists to keep a
  write-only drop directory unreadable, and no CLI flag can produce one.
  `--allow-write` grants `Read` alongside the write axis — keyed to
  `axis.grants().write` so a future write-conferring axis inherits the
  affordance — and
  [decision-axis-table.md](../decision-axis-table.md#the-cli-departs-from-the-table-once)
  settles that departure by noting the narrow form stays reachable through
  `SandboxPolicy::allow_write` (#49). True, and it leaves the asymmetry the
  longest comment in `rights.rs` defends invisible to every operator: the shape
  is a library-only affordance, while the flag surface has exactly one write
  grant and it is a read grant too. The record weighs the *flags* not drifting
  apart, which is a real property; it does not weigh whether an operator who
  wants a drop directory has any way to ask for one. `SECURITY.md` carries the
  pair under *Not vulnerabilities* rather than as a gap, which is the reading
  worth pushing on.

## The path that is opened has to be the path that was granted

Everything above is pure: it maps a policy to bits with no I/O. The remaining
question is the one neither `compat` nor `rights` can answer — whether the
directory the kernel is about to be told about is the directory the harness
judged.

It can differ, because the two happen in different processes at different times.
The policy is vetted in the harness; the rules are opened in stage 2. Between
them a symlink in the path can be re-pointed (#205), or a `rename(2)` can put a
different real directory at the same name with the spelling left identical
(#212). Those are two different attacks and
[`opened.rs`](../../crates/sandbx-core/src/helper/ruleset/opened.rs) asks two
different questions about them.

`open_grant` is the only place in the crate that produces a `PathFd`, so no
rule can be added anywhere that skips either check. It opens with
`O_PATH | O_CLOEXEC` and no `O_NOFOLLOW` — a lookup rather than an access, and
one that deliberately follows every component, so the descriptor may well name
an inode no part of the spelling pointed at when it was vetted. Catching that is
the next two steps' job, not the open flags'.

**First the spellings.** `reads_back` reads `/proc/self/fd/<n>` and returns the
path the kernel says that descriptor names. Mismatch is `GrantRedirected`,
carrying both the granted spelling and what it opened as. This runs for every
rule, including the resolver files the helper bind-mounted itself: one of those
redirected under the bind is still a rule on an inode sandbx did not place. Two
incidental kernel details make the readback work at all, and the comment keeps
both: a task may always read its own `fd/` directory, and `execve` resets the
dumpable flag that permission turns on, so neither sandbx clearing its own flag
nor the supervisor clearing one reaches this stage.

**Then the object.** For a grant — and only for a grant — the descriptor is
`fstat`ed and the `(dev, ino)` compared against the pin the harness carried
across:

```rust
    let RuleTarget::Granted(granted) = target else {
        return Ok(fd);
    };

    let object = ObjectId::of_fd(&fd)?;
    if object != granted.object() {
        return Err(SandboxError::GrantReplaced {
            granted: granted.path().to_path_buf(),
            vetted: granted.object(),
            opened: object,
        });
    }
```

`let` … `else` is the Rust corner worth pausing on: it binds when the pattern
matches and otherwise runs a block that must diverge, which here means
`RuleTarget::Installed` leaves with the descriptor and no pin check. That is not
a trust judgement about the helper's own files. It is that the helper has no
*second* answer to compare against — the bind mount was made in this process,
moments earlier, so a pin taken here would be one process agreeing with itself.
`an_installed_path_is_not_pinned_to_the_object_under_it` pins the asymmetry.

Why two errors rather than one: they answer different questions. The readback
asks whether the name still leads where it led; the stat asks whether the thing
at the end of it is the same thing. An operator reading `GrantRedirected` has a
substituted *path* to go and look at. One reading `GrantReplaced` has one name
and two objects, and no path anywhere will show them the difference.
[decision-grant-identity.md](../decision-grant-identity.md) keeps the full
refusal table; the four shapes that reach this file are:

| what happened | what notices | refusal |
|---|---|---|
| the granted spelling opens as another path | the readback | `GrantRedirected` |
| another real directory sits at the granted name | the `fstat` | `GrantReplaced` |
| the readback cannot be taken at all | `reads_back` | `Unsupported` |
| the `fstat` cannot be taken at all | `ObjectId::of_fd` | `Unsupported` |

The last two rows are the detail most easily got wrong. A readback that fails is
*not* reported as `GrantRedirected`, which would claim to know where the grant
went; a stat that fails is not reported as `GrantReplaced`, which would accuse
the grant of a swap that may not have happened. A sandbox whose rules cannot be
confirmed is one this kernel will not enforce, so both refuse as that.

After the rule is added there is no window left to narrow. `PathBeneath` holds
the descriptor, so the kernel attaches the rule to that inode — a later rename
moves the name and not the rule.

## A grant is pinned to an object, not to a name

The pin itself lives in
[`policy/vetted.rs`](../../crates/sandbx-core/src/policy/vetted.rs). `ObjectId`
is a `(dev, ino)` pair, compared and never interpreted; `VettedPath` is a
resolved path and the `ObjectId` it named when it was vetted. Neither half of
the pair is stable across a remount, which is exactly the property that makes
the pair worth carrying: an object that moved is not the one that was vetted,
whatever it is now called.

There are two producers, and the asymmetry between them is the design:

| producer | runs in | what it does |
|---|---|---|
| `VettedPath::vet` | the harness | canonicalize, then stat |
| `VettedPath::from_wire` | the helper | reads the pin off argv, no I/O at all |

`vet` is the only producer that touches the filesystem, and it must stay that
way. `HelperArgs::decode` builds a policy through the same `grant` entry point
inside the helper — the process a grant is meant to be safe *from* — so
resolving or stat'ing there would measure whatever the links point at by then,
and the comparison would be against the attacker's own answer. `from_wire` is
not a weaker source: argv is the harness's own, passed from stage 1 to stage 2
verbatim, and the path token has always been trusted on exactly that basis. What
the pin removes is the reliance on the *filesystem* agreeing between the two
processes, which is the only party the seam was ever exposed to.

**What an unpinned grant would cost is a claim, not a race.** `SandboxPolicy` is
public and so are its builders, so if `grant` took a bare path the inode
comparison would become opt-in — and the caller who would most benefit from it
is precisely the one who would not know to ask. `SECURITY.md` claims
default-deny at the library level because that is the level that is a boundary,
and a guarantee that holds for the CLI and lapses for an embedder is a claim
the code no longer earns. So the pin travels *inside* the grant: `grant` takes
nothing but a `VettedPath`, there is no unpinned state for the helper to have a
policy about, and an embedder meets the decision as a signature change at
`cargo build` rather than as a refused run. The refusal still exists — `decode`
rejects a wire grant with no pin — but nothing in the crate can construct one.

The floor on what the pair can mean is stated where it is taken: an inode number
is reused once its object is unlinked, so a granted directory *deleted and
re-created* at the same name can compare equal although nothing the harness
judged survives. `SECURITY.md` carries that as a non-claim with the host it was
measured on. Worth separating from the attack the pin does close: a `rename(2)`
substitution puts a directory that *already exists* at the granted name, and an
existing directory cannot be holding the vetted inode number while the vetted
object still holds it — so the pin sees that one every time.

- **Worth questioning:** the remedy that needs no pin at all was rejected on a
  lint. [decision-grant-identity.md](../decision-grant-identity.md) prices
  inheriting the harness's own `O_PATH` descriptor through the `exec` — nothing
  to re-resolve helper-side, no third argv token, no comparison to get wrong —
  and declines it because receiving a descriptor needs `from_raw_fd` and passing
  one needs `pre_exec`, both `unsafe` against a workspace-wide
  `unsafe_code = "forbid"` that no crate overrides. The record is explicit that
  this is "rejected on the lint, not on the design". What it does not do is
  price the lint against what the fallback gives up, which its own *What it
  costs* section enumerates: a reused inode reads as the vetted object, and an
  anonymous `st_dev` makes a network-mount remount read as a substitution. A
  held descriptor has neither limit, because it pins the object instead of a
  number naming it. The interesting question is not whether `unsafe` is worth
  avoiding in general, but whether a `forbid` with no documented carve-out
  procedure should be able to outrank the stronger mechanism for a property
  `SECURITY.md` makes a claim about — and if it should, whether the two named
  limits belong in the claim table rather than only in the non-claims.

## You should now be able to explain

- Why Landlock needs an ABI *floor* rather than a preference, in terms of what
  happens to an access type that is not in the handled set.
- Which single error from the kernel makes the negotiation step down a rung, and
  why stepping down on any other error would be a hole.
- Why the kernel probe asks about the network axis even for a run that is
  granted no network.
- Why a partly enforced ruleset is refused, and why asking best-effort for the
  newest ABI would have made that refusal impossible to keep.
- Why read rights are written as `from_read` minus `Execute` and write rights as
  `from_all` minus the whole read set, and what the second subtraction protects.
- Which axis confers execute, and why no union of grants can reach it.
- What `GrantRedirected` and `GrantReplaced` each mean, and why one error for
  both would tell an operator less than either.
- Why the helper never resolves or stats a granted path for itself, and why an
  installed resolver file is not pinned.
- Why `SandboxPolicy::grant` takes a `VettedPath` rather than a path plus an
  optional pin.

## Next

[10 — the syscall filter](10-seccomp.md), which is the other half of the same
box: everything an escape could reach without ever naming a path.
