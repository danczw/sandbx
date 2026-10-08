# The enforcement seam

Where policy stops being data and becomes something the kernel holds. There are
**two** seams, not one, and most tools only cross the first.

## Seam 1 — `FsGuard`, in-process

Six of the seven built-ins (`read`, `write`, `edit`, `ls`, `grep`, `find`) never
spawn anything, so Landlock never sees them. For those, `FsGuard` *is* the
enforcement.

```
SandboxPolicy ──► FsGuard::new ──► readable[] / writable[]     (execute discarded)
                       │
                       └──► open_read / open_write  ──► O_NOFOLLOW handle
                            walk_readable           ──► ReadableWalk { files, truncated }
                            read_dir                ──► ReadDir        ◄── ls only
                            check_read / check_write ─► resolved path  ◄── no tool
```

Tools hold **handles, not paths**. That is what closes the TOCTOU window: if the
leaf became a symlink between check and use, the open fails. `ls` is the one
exception: `FsGuard::read_dir` hands it a `ReadDir`, but there is no `O_NOFOLLOW`
for a directory read, so that handle closes the window no more than a path would.

### The root is confirmed, not re-resolved

A root the guard holds is the grant's own vetted path, pin included, and never a
second resolution of its spelling. `FsGuard::new` does no I/O: a granted path
resolves to itself by the invariant on `SandboxPolicy::grant`, so there is nothing
left to resolve, and a `canonicalize` whose result is discarded but whose success
gates the check below it is the substitution one size down — a granted root replaced
by a symlink had the guard adopt the link's target as its root (#212).

So containment is two questions, both of which must answer yes: the requested path
is lexically inside a root, and that root still holds the object the grant carries,
measured now through an `O_PATH` descriptor. A mismatch is `root_replaced` — the
in-process twin of the helper's `grant_replaced`, decided here because there is no
descriptor to carry and no second process to relay it (`decision-grant-identity.md`).

The confirmation is measured **once** per access and carried into the refusal. Asking
for a `bool` and then re-measuring to learn which root moved is two measurements that
can disagree, and the disagreeing case emits the wrong refusal for a root that now
confirms. A root that cannot be opened at all names no object to accuse: it grants
nothing and refuses nothing, so the scan continues and an unmeasurable root reads as
out of bounds rather than as a swap.

The scan short-circuits on the first root that is both lexical and confirmed, because
nested and sibling grants overlap — a replaced root must not deny a path a second
grant legitimately covers.

### A refusal says nothing, except inside a grant

`canonicalize` fails differently for a missing path (ENOENT), an unreadable
parent (EACCES) and a path that resolves out of bounds. Handing the difference
back makes the guard a filesystem oracle, and the refusal travels inside a
`tool_result` — so a prompt-injected model can map the host with it. Every
refusal outside the roots is therefore the same refusal.

`conceal_unless_granted` is the one exception, and it has a single rule: the
nearest ancestor that *does* resolve decides, **and must speak for the path
below it.** It does not if a symlink sits in between: the link is in-grant by
spelling and its target is anywhere, so a dangling one planted in a granted root
would answer "does this host path exist" for any target the agent names — the
oracle in the shape the ancestor rule alone cannot see. `reaches_plainly`
therefore conceals anything reached through a symlink, and a `..` with it, which
leaks nothing but would print an out-of-grant path as an absence's subject. So a
symlink in a grant is refused the way an out-of-bounds path is, whatever stopped
it: `contains` tests a *resolved* path, and one that will not resolve is inside
no root. That costs the loop case a precise reason, which is the price of the three
failures reading alike.

A replaced root would open the same oracle one bit wide. If concealment treated an
unconfirmed root as plainly out of bounds, a *present* file under the substitute
would come back `root_replaced` and an absent one `path_not_allowed` — "does this
name exist under the directory you swapped in", answerable by reading the label.
Both routes therefore pass through one refusal site, so the two cases read alike;
`a_substituted_root_conceals_an_absence` compares the labels and nothing else.

One refusal site is not enough on its own, because the oracle comes back through
what reaches it. The root question is asked on the **requested spelling**,
lexically, before anything is resolved — `moved_root`, at each of the four sites
that can refuse. Asked after resolution instead, in either of the two forms that
look equivalent, the substitute picks the verdict: a link it holds may resolve
*into a second grant that confirms*, which reads as plainly inside and returns
`Ok` beside an absent name's `root_replaced`; and a nearest-resolving-ancestor
measurement follows that same link past the root being asked about. The first cost
a write a new file under a root the policy no longer holds. The rule to keep is
that no reason may be drawn from a path the substitute resolved.

Lexically means two spellings, not one, because neither covers the other.
`Path::starts_with` is a whole-component prefix test, so a `..` *after* the root
name does not undo the match — `granted/link/../..` names the root while its
collapse leaves it — and a `..` *before* the root name reaches it without naming
it in front, so `other/../granted` matches only once collapsed. Either form
matching refuses, and the collapse is skipped when it equals the spelling, each
candidate root costing an open and an `fstat`.
`a_detour_through_dot_dot_does_not_evade_the_root` and
`a_dot_dot_after_the_root_still_names_it` pin one form each. The collapse is not a
`canonicalize` and must not be mistaken for one: a `..` above a symlink collapses
to the link's parent lexically and to its target's parent in the kernel. That is
why it is one of two forms tested rather than the form tested — and why the
verdict itself still comes from the resolved path, which `contains` admits only
under a root that confirms.

Asking on the spelling is also not enough, because the resolution still reaches a
substituted root the spelling cannot see: a link planted in a root that
*confirms*, which the model can write in the default policy. So the three sites
that answer a caller draw no reason from the resolution at all. Once the spelling
has declined to accuse a root, the refusal is plainly outside, present and absent
alike — `a_link_planted_in_a_confirmed_root_conceals_an_absence`. The walk is the
fourth site and keeps its measurement: it records the reason and skips the entry,
with no reason returned for a caller to read a bit off. The cost is a trail that
says `path_not_allowed` where the substitution was reached only by resolving, and
that is the right way round — the operator still gets `root_replaced` for every
root a path names, and the one who cannot tell the two apart is the one probing.

A granted name that has become a symlink falls out of the same rule rather than
needing its own. `confirm` omits `O_NOFOLLOW`, so the object it measures is the
link's target: a name leading elsewhere holds something else, and the access is
`root_replaced` — not the `path_not_allowed` a lexical-only guard reported, which
also differed from what an absent name under that root reported. A link naming the
vetted object itself is the one that confirms, and the resolved path then leaves
the granted spelling, so that access refuses as plainly outside —
`a_root_linked_back_to_its_vetted_object_is_refused_as_outside`. Refused either
way, and the two labels are what an operator counts substitutions by.

Where the ancestor does speak for the path, the caller could enumerate the
directory anyway, so absence there is honest, and it is `SandboxError::NotFound`,
which `sandbx-tools` maps to `ToolError::Failed` rather than `Denied` (#180) and
the trail records as `absent` (#187). Outside a grant it is a `denied` like any
other: naming the absence there would disclose over the trail what the refusal
conceals.

What counts as absence is `names_nothing`: ENOENT, ENOTDIR and ENAMETOOLONG, by
errno because `ErrorKind` cannot spell the last one. The line is what the agent
can act on — a wrong name is its to fix — so EACCES from a `000` directory keeps
`Unresolvable` and its `denied` record. Narrowing it to ENOENT alone sent a path
through a regular file back as a refusal, which is #180's own failure mode one
errno over — except on the leaf of a directory read, where ENOTDIR says the leaf
*is* a file and `listed_nothing` drops it.

Both entry points go through the gate. `check_write` resolves the parent, not the
leaf, and reports the path the caller asked for rather than the parent that
failed.

## Seam 2 — argv, into the helper process

The policy crosses *two* process boundaries as argv:

```
sandbx ──argv──► helper stage 1 (supervisor) ──argv verbatim──► stage 2 ──► apply()
```

| | |
|---|---|
| Shape | `HelperArgs { policy, program, args, pin }`, `encode` / `decode`. `pin` rides beside the policy and not inside it, for the reason `context/decision-pinned-entry-point.md` gives |
| Path flags | `--ro` / `--rw` / `--rx`, from the single `path_flag(axis)` match |
| Other flags | `--allow-network`, `--allow-network-port N` (repeatable), `--allow-unix-sockets`, `--env NAME` (repeatable), `--dns-over-tcp`, `--pin-sha256 HEX` (at most once), `--` separator |
| Wire ≠ CLI | the two spellings diverge where they must. `--allow-network-port` takes exactly one value, where the CLI's `--allow-network` takes an optional one: `decode` walks argv a token at a time and must refuse anything unrecognised, so an optional value would put a "does this look like a port?" lookahead in the decoder that gates enforcement. Same reason `--env NAME` is not spelled `--allow-env` here. `--dns-over-tcp` *is* the CLI spelling, and may be: it takes no value, so there is no lookahead to get wrong — and so is `--pin-sha256`, whose one value is mandatory on both sides |
| Why argv | the environment is now cleared at every stage (#98), so it cannot carry the policy — argv is the only channel left that survives the re-exec. It is not *private*: the command reads its own `/proc/self/cmdline`, so the rule is that argv carries variable **names**, never values. `--dns-over-tcp` keeps that rule rather than bending it: the pair it stands for is a constant the policy holds, so the wire carries the flag and not the value |
| Decode failure | always a refusal; an unrecognised flag is an error, never skipped |
| Stage 1 → 2 | argv passed **verbatim**, not re-encoded — a re-encode is a second chance for the policy to drift on its way to the stage that enforces it |

`axis_for` is a reverse lookup over `path_flag`, so a flag `encode` can emit is
one `decode` accepts by construction — the wire spelling exists in exactly one
place.

**Which side is trusted: neither.** The helper only ever narrows. Stage 2 takes a
supervisor pid as a positional token, but that is a *liveness* check, not an
authorization one — nothing in the argv is a trust boundary.

`HelperDispatch` has two variants and **no success arm**, and is `#[must_use]`:
a failed helper run cannot fall through to unrestricted execution.

## The Landlock seam itself

```
rights_for(axis: Axis, target_is_dir: bool, abi: landlock::ABI) -> BitFlags<AccessFs>
fs_rules(policy: &SandboxPolicy, abi: landlock::ABI) -> [(Axis, &Path, BitFlags<AccessFs>)]
net_rules(policy: &SandboxPolicy, abi: landlock::ABI) -> RequestedNet<'_>
                                                                      helper/ruleset/rights.rs
handled_access(abi: landlock::ABI) -> BitFlags<AccessFs>
handled_net_access(abi: landlock::ABI) -> BitFlags<AccessNet>
kernel_probe(abi: landlock::ABI) -> Result<(), RulesetError>
negotiated_abi_from(probe: impl FnMut(ABI) -> Result<(), RulesetError>) -> Result<ABI, _>
negotiated_abi() -> Result<ABI, _>
enforcement_verdict(status: RulesetStatus) -> Result<(), _>
                                                                      helper/ruleset/compat.rs
Requested { handled: BitFlags<AccessFs>, rules: [(Axis, &Path, BitFlags<AccessFs>)],
            net: RequestedNet }
RequestedNet::Unhandled | ::Ports { handled, granted: BitFlags<AccessNet>, ports: &[u16] }
requested_at(policy: &SandboxPolicy, abi: landlock::ABI) -> Requested<'_>
requested(policy: &SandboxPolicy) -> Result<Requested<'_>, _>
                                                                      helper/ruleset/mod.rs
```

The syscall list is in `helper/seccomp/rules.rs`; `apply` in `helper/mod.rs`.

`abi` is a **parameter**, not ambient — that is what makes the mapping
kernel-independent and testable at both ends of the range. The stronger form
since #87: a parameter to `requested_at`, and **`apply` holds no ABI binding at
all.** `requested` negotiates internally and returns the handled set and the
rules together, so the two cannot be derived from different ABIs. Previously they
were two expressions in `apply` with a comment between them saying they must
match — and because `AccessFs::from_all` is constant across V5..V8, a divergence
there was unobservable in any kernel-free test. Structure, not coverage, is what
retires it; `fs_rules` narrowed to `pub(super)` so `apply` cannot reach past the
join.

`negotiated_abi_from` takes the probe for the same reason `fs_rules` takes the
policy: the decision worth asserting is not the ladder walk but which errors are
an *ABI verdict* (step down a rung) and which are not (refuse). `RulesetError` was
named in exactly one place in the workspace and no test constructed one, so the
refusing arm was not merely untested but unreachable (#87).

`apply` ignores the axis (`for (_, path, rights)`): the kernel is told the rights
and nothing else. The axis rides along only so tests can assert the mapping.

### Why the axis rides along

`read | write` unioned and checked for `Execute` is how "no grant implies
execute" gets asserted without a kernel. **It is per-spelling, not per-inode:**
two grants reaching one inode by different spellings (`/usr/bin` and
`/usr/bin/`) are unioned by the kernel and counted apart here. So it is not the
kernel's own answer for an arbitrary policy — it is the answer for a policy that
names one path one way.

### `apply` needs only a Landlock-capable kernel

Not root, and not namespaces. It runs with an empty capability set, in a
*different process* from the one that made the namespaces — `prepare_supervisor`
does the `unshare` and the capability drops in stage 1. The design is
unprivileged-userns throughout; the boundary the diagram draws is a **process**
boundary, crossed by argv.

## Derived vs. hard-coded expectations

The trap: a test that derives its expectation from the same table as the code
asserts only that the code is self-consistent. Flip a row in the table and both
move together.

| Site | Derived from `grants()` | Hard-coded |
|---|---|---|
| `rights_for` / `fs_rules` | ✓ | |
| `FsGuard::new` buckets | ✓ | |
| `encode` / `decode` | ✓ | |
| `requested_at` | ✓ (it is `handled_access` + `fs_rules` + `net_rules`) | |
| `each_axis_confers_exactly_the_documented_set` | | ✓ `make_bitflags!`, both ABI ends |
| `rights_for_narrows_a_regular_file` | | ✓ `file_legal` spelled out |
| the three `negotiated_abi_from` tests | | ✓ error chains built by hand; which variant steps down is spelled out |
| `the_handled_set_and_the_rules_come_from_one_abi` | ✓ — see below | ✓ `ResolveUnix` named |
| audit counts | | ✓ exhaustive `match` |
| `Grants::paths` | | ✓ exhaustive `match` |

The hard-coded rows are the ones that would fail if `Axis::Write` were flipped to
`execute: true`. The two exhaustive matches are what make a *new* axis a build
failure — not the length of `Axis::ALL`, which nothing needs at compile time.

**The ABI-agreement row is derived, against this table's own thesis, and that is
a limit rather than an oversight.** Its union check is a *theorem*: `rights_for`'s
three subtractions partition `from_all`, and landlock's own invariant test asserts
`from_read | from_write == from_all`, so the union equals the handled set at every
ABI — including one the code got wrong. No hard-coded expectation is available to
replace it, because pinning `handled` literally would make a third site spelling
out the same sixteen-or-seventeen rights, against the "one place to edit" argument
that `each_axis_confers_exactly_the_documented_set` rests on. So the test carries
two assertions that are *not* derived and do the real work: that the handled set
differs between `BASELINE_ABI` and `LATEST_ABI` — the only thing that catches a
`requested_at` ignoring its `abi`, or both halves pinned to one rung — and that
`ResolveUnix` is the bit on which they differ, named so a floor bump past V9 fails
here loudly instead of turning the inequality into a tautology. `from_all` is
constant across V5..V8, so that one bit is the entire kernel-free discriminating
power available in the negotiable range.

## #52's five items

| # | Item | Where it landed |
|---|---|---|
| 1 | `fs_rules` untestable without root | split out, asserted with no kernel |
| 2 | nothing asserted the axis→rights mapping | asserted |
| 3 | nothing pinned the *exact* right set | #74 — `each_axis_confers_exactly_the_documented_set` pins every axis's whole `BitFlags` at `BASELINE_ABI` and `LATEST_ABI`, and asserts a row exists per `Axis::ALL` |
| 4 | partial enforcement accepted | #76 — `enforcement_verdict` refuses it |
| 5 | per-endpoint egress | #42 — a TCP port allowlist, which is all the kernel can match on. Per-host is not enforced and needs a userspace proxy, which `decision-egress-proxy.md` declines: the interception it would rest on is cooperation. One piece of it is claimable, a resolver bounding which names resolve (#145) |

53 real-kernel enforcement tests, split by what enforces them: 39 in
`tests/enforcement.rs` for paths and grants, 8 in `tests/enforcement_syscalls.rs`
for the calls Landlock cannot express, 6 in `tests/enforcement_network.rs` for
the ports it does. All three files are
`#![cfg(all(feature = "sandbox-integration", target_os = "linux"))]`, so the
count is unconditional — all 53 run or none of the files compiles, and
`cargo test` reports `0 ignored`. Nothing checks this number against the files.
