# Policy and grants: one table, two seams, and what a grant may reach

## The enforcement seam

Where policy stops being data and becomes something the kernel holds. There are
**two** seams, not one, and most tools only cross the first.

### Seam 1 — `FsGuard`, in-process

Six of the seven built-ins (`read`, `write`, `edit`, `ls`, `grep`, `find`) never
spawn anything, so Landlock never sees them. For those, `FsGuard` *is* the
enforcement.

```
SandboxPolicy ──► FsGuard::new ──► readable[] / writable[]     (execute dropped, not the path)
                       │
                       └──► open_read / open_write  ──► File
                            walk_readable           ──► ReadableWalk { files, truncated }
                            read_dir                ──► Listing        ◄── ls only
                            check_read / check_write ─► resolved path  ◄── no tool
```

`Axis::ReadExecute` confers read, so an `--allow-exec` path still lands in
`readable[]`: what `FsGuard::new` drops is the execute right, not the path.

Tools hold **handles, not paths**, which is what closes the TOCTOU window. Where
a granted root is a directory and the kernel has `openat2` (5.6), an access
resolves beneath a descriptor held on that root with `RESOLVE_NO_SYMLINKS`, so a
component swapped for a link fails the open. Otherwise an open goes by path with
`O_NOFOLLOW`, which guards the leaf only, and `ls` lists by path, a second
resolution (`fs_guard.rs`'s `//!`, #230).

#### The root is confirmed, not re-resolved

A root the guard holds is the grant's own vetted path, pin included, and never a
second resolution of its spelling: a granted path resolves to itself by the
invariant on `SandboxPolicy::grant`. `FsGuard::new` opens a descriptor on it
(`open_root`) and keeps it only if it measures as the pinned object. A
`canonicalize` of the root, discarded but gating the check, is the substitution
one size down — a root replaced by a symlink had the guard adopt the link's
target (#212).

So containment is two questions, both of which must answer yes: the requested path
is lexically inside a root, and that root still holds the object the grant carries,
measured now through an `O_PATH` descriptor. A mismatch is `root_replaced` — the
in-process twin of the helper's `grant_replaced`, decided here because there is
no second process to relay it (*A grant names an object, not a name*, below).

The confirmation is measured **once** per access and carried into the refusal. Asking
for a `bool` and then re-measuring to learn which root moved is two measurements that
can disagree, and the disagreeing case emits the wrong refusal for a root that now
confirms. A root that cannot be opened at all names no object to accuse: it grants
nothing and refuses nothing, so the scan continues and an unmeasurable root reads as
out of bounds rather than as a swap.

The first root that is both lexical and confirmed settles the verdict, because
nested and sibling grants overlap — a replaced root must not deny a path a
second grant legitimately covers.

#### A refusal says nothing, except inside a grant

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
measurement follows that same link past the root being asked about. The first
would let a write create a new file under a root the policy no longer holds. The
rule to keep is that no reason may be drawn from a path the substitute resolved.

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
`root_replaced`, as an absent name under that root is. A link naming the vetted
object itself is the one that confirms, and the resolved path then leaves the
granted spelling, so that access refuses as plainly outside —
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
`Unresolvable` and its `denied` record. ENOENT alone would send a path through a
regular file back as a refusal, #180's own failure mode one errno over — except
on the leaf of a directory read, where ENOTDIR says the leaf *is* a file and
`listed_nothing` drops it.

Both entry points go through the gate. `check_write` resolves the parent, not the
leaf, and reports the path the caller asked for rather than the parent that
failed.

### Seam 2 — argv, into the helper process

The policy crosses *two* process boundaries as argv:

```
sandbx ──argv──► helper stage 1 (supervisor) ──argv verbatim──► stage 2 ──► apply()
```

| | |
|---|---|
| Shape | `HelperArgs { policy, program, args, pin }`, `encode` / `decode`. `pin` rides beside the policy and not inside it, for the reason `context/decision-helper-audit-channel.md` gives |
| Path flags | `--ro` / `--rw` / `--rx`, from the single `path_flag(axis)` match, each taking a path and its `<dev>:<ino>` pin |
| Other flags | `--allow-network`, `--allow-network-port N` (repeatable), `--allow-unix-sockets`, `--dns-over-tcp`, `--env NAME` (repeatable), `--allow-dns-name NAME` (repeatable), `--pin-sha256 HEX` (at most once), `--` separator |
| Wire ≠ CLI | the two spellings diverge where they must. `--allow-network-port` takes exactly one value, where the CLI's `--allow-network` takes an optional one: `decode` walks argv a token at a time and must refuse anything unrecognised, so an optional value would put a "does this look like a port?" lookahead in the decoder that gates enforcement. Same reason `--env NAME` is not spelled `--allow-env` here. `--dns-over-tcp` *is* the CLI spelling, and may be: it takes no value, so there is no lookahead to get wrong — and so is `--pin-sha256`, whose one value is mandatory on both sides |
| Why argv | the environment is cleared at every stage, so it cannot carry the policy — argv is the only channel that survives the re-exec. It is not *private*: `/proc` in the sandbox is the host's, so the command reads the supervisor's `/proc/<pid>/cmdline` — not its own, which the `exec` overwrites — and the rule is that argv carries variable **names**, never values. `--dns-over-tcp` keeps that rule rather than bending it: the pair it stands for is a constant the policy holds, so the wire carries the flag and not the value |
| Decode failure | always a refusal; an unrecognised flag is an error, never skipped |
| Stage 1 → 2 | argv passed **verbatim**, not re-encoded — a re-encode is a second chance for the policy to drift on its way to the stage that enforces it |

`axis_for` is a reverse lookup over `path_flag`, so a flag `encode` can emit is
one `decode` accepts by construction — the wire spelling exists in exactly one
place.

**Which side is trusted: neither.** The helper only ever narrows. Stage 2 takes a
supervisor pid as a positional token, but that is a *liveness* check, not an
authorization one — nothing in the argv is a trust boundary.

`with_helper_dispatch` is the only entry. It takes the ordinary path as a closure
the helper arms cannot reach, each arm matches a `Result<Infallible, _>` and so
has **no success case**, and its exit code is `#[must_use]`: a failed helper run
cannot fall through to unrestricted execution.

### The Landlock seam itself

```
rights_for(axis: Axis, target: Inode, abi: landlock::ABI) -> BitFlags<AccessFs>
fs_rules(policy: &SandboxPolicy, abi: landlock::ABI) -> [FsRule]
FsRule { axis: Axis, target: RuleTarget, rights: BitFlags<AccessFs> }
RuleTarget::Granted(&VettedPath) | ::Installed(&'static Path)   ──► path()
net_rules(policy: &SandboxPolicy, abi: landlock::ABI) -> RequestedNet<'_>
                                                                      helper_ruleset_rights.rs
handled_access(abi: landlock::ABI) -> BitFlags<AccessFs>
handled_net_access(abi: landlock::ABI) -> BitFlags<AccessNet>
kernel_probe(abi: landlock::ABI) -> Result<(), RulesetError>
negotiated_abi_from(probe: impl FnMut(ABI) -> Result<(), RulesetError>) -> Result<ABI, _>
negotiated_abi() -> Result<ABI, _>
enforcement_verdict(status: RulesetStatus) -> Result<(), _>
                                                                      helper_ruleset_compat.rs
Requested { handled: BitFlags<AccessFs>, rules: [FsRule], net: RequestedNet }
RequestedNet::Unhandled | ::Ports { handled, granted: BitFlags<AccessNet>, ports: &[u16] }
requested_at(policy: &SandboxPolicy, abi: landlock::ABI) -> Requested<'_>
requested(policy: &SandboxPolicy) -> Result<Requested<'_>, _>
                                                                                  requested.rs
```

The syscall list is in `helper_seccomp_rules.rs`; `apply` in `helper_exec.rs`.

A rule names a `RuleTarget`, not a path: `Granted` carries the object the harness
vetted and `Installed` is a resolver file the helper bind-mounted, so
`open_grant` checks the pin on one and has nothing to check on the other
(*A grant names an object, not a name*, below).

`abi` is a **parameter**, not ambient — that is what makes the mapping
kernel-independent and testable at both ends of the range. It is a parameter to
`requested_at`, and **`apply` holds no ABI binding at all**: `requested`
negotiates internally and returns the handled set and the rules together, so the
two cannot be derived from different ABIs. Do not split them back into two
expressions in `apply`: `AccessFs::from_all` is constant across V5..V8, so a
divergence there is unobservable in any kernel-free test. Structure, not
coverage, is what rules it out; `fs_rules` is `pub(super)` so `apply` cannot
reach past the join.

`negotiated_abi_from` takes the probe for the same reason `fs_rules` takes the
policy: the decision worth asserting is not the ladder walk but which errors are
an *ABI verdict* (step down a rung) and which are not (refuse). Without the seam
no test can construct a `RulesetError`, and the refusing arm is unreachable
(#87).

`apply` ignores the axis (`for FsRule { target, rights, .. }`): the kernel is
told the rights and nothing else. The axis rides along only so tests can assert
the mapping.

#### Why the axis rides along

`read | write` unioned and checked for `Execute` is how "no grant implies
execute" gets asserted without a kernel. **It is per-spelling, not per-inode:**
two grants reaching one inode by different spellings (`/usr/bin` and
`/usr/bin/`) are unioned by the kernel and counted apart here. So it is not the
kernel's own answer for an arbitrary policy — it is the answer for a policy that
names one path one way.

#### `apply` needs only a Landlock-capable kernel

Not root, and not namespaces. It runs with an empty capability set, in a
*different process* from the one that made the namespaces — `prepare_supervisor`
does the `unshare` and the capability drops in stage 1. The design is
unprivileged-userns throughout; the boundary the diagram draws is a **process**
boundary, crossed by argv.

### Derived vs. hard-coded expectations

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
ABI — including one the code got wrong. That is a partition only with the
unix-socket flag set: the write axis subtracts `ResolveUnix` as well, and the
flag is what puts it back (#259). That is why the test's policy sets the flag,
and why dropping it from the policy to "simplify" the test makes the union fall
short of `handled` at `LATEST_ABI`. No hard-coded expectation is available to
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

### A new axis without a row fails the test

`each_axis_confers_exactly_the_documented_set` asserts its own expectation table
against `Axis::ALL.len()`, so a fourth axis cannot be added without a row
spelling out its whole `BitFlags` at both ABI ends. The exhaustive matches above
make a new axis a build failure; this makes it a test failure until its rights
are written down.

### All of them run, or none of the files compiles

65 real-kernel enforcement tests in `sandbx-helper`, split by what enforces them:
41 in `enforcement.rs` for paths and grants, 10 in `enforcement_syscalls.rs` for
the calls Landlock cannot express, 6 in `enforcement_network.rs` for the ports
it does, and 8 in `enforcement_resolver.rs` for the names that resolve. All four
files are `#![cfg(all(feature = "sandbox-integration", target_os = "linux"))]`,
so the count is unconditional — all of them run or none of the files compiles,
and `cargo test` reports `0 ignored`. Nothing checks this number against the
files.

## The axis table

Why filesystem policy has one table and five consumers instead of five parallel
lists. The current derived-vs-forced breakdown lives in *Derived vs. hard-coded
expectations*, above; this is what each consumer derives and how that was
checked.

### The table

```rust
pub enum Axis { Read, Write, ReadExecute }          // closed. No dyn, no #[non_exhaustive]
pub struct Grants { read: bool, write: bool, execute: bool }

Axis::Read        => (true,  false, false)
Axis::Write       => (false, true,  false)
Axis::ReadExecute => (true,  false, true )
```

### The five consumers

| Site | Derives by |
|---|---|
| `helper_ruleset_rights.rs` | loop over `Axis::ALL`, rights from `grants()` |
| `fs_guard.rs` | destructure `grants()` into readable/writable |
| `helper_args.rs` | one `path_flag` match, `axis_for` as reverse lookup |
| `audit_event.rs` | loop + exhaustive `match` |
| `sandbx-grants/src/grants.rs` | loop + exhaustive `match` |

Two sites cannot derive their answer and are **forced** instead — `tracing` needs
static field names, and clap needs per-flag `--help` text. Both pair the loop
with an exhaustive `match`, so a new axis is a build failure rather than a
silently missing grant. Not fixed-arity destructuring of `Axis::ALL`, which was
tried and reverted: nothing needs the array's length at compile time, and the
exhaustive matches are the whole mechanism.

### Why the rights are subtractions

```
read  = from_read(abi) & !Execute
write = from_all(abi)  & !from_read(abi) & !ResolveUnix
exec  = read | Execute        ← so read | Execute == from_read(abi)
unix  = from_all(abi)  &  ResolveUnix    ← from the flag, not from an axis
```

Stated as what each axis *removes* from the kernel's own sets, not as an
enumeration of what it grants. A right added by a future ABI lands in `from_all`
and is denied by `allow_read` automatically, rather than being permitted until
someone notices.

It runs the other way on the write axis, which is the cost of the second line and
not an oversight. `write` is the complement of the read set within `from_all`, so
a new right the kernel does not put in `from_read` is *conferred* by
`allow_write` automatically — permitted until someone notices, on the widest axis
there is. Subtracting the whole read set rather than `Execute` alone is what buys
it: one bit less and a write grant confers read at the kernel that `FsGuard`
refuses, leaving the write-only drop directory readable (`rights_for`'s `///`).

`ResolveUnix` is the worked example rather than a hypothetical, and the one
exception. It arrived at ABI V9 and would have joined the write set with no line
edited, so on the first V9 kernel (Linux 7.1, `LATEST_ABI`)
`--allow-unix-sockets` — one boolean, documented as all-or-nothing — would have
acquired a path condition: a pathname socket would have to sit inside a *write*
grant to be dialled, and a command that works on V8 would fail on a newer kernel
with the same flags. So the write axis subtracts it and the flag confers it
instead, on every path the policy granted, masked by `from_all(abi)` so nothing
moves at or below V8 (#259).

Four shapes were rejected, and the first is the one someone will re-propose:

- **Leave `ResolveUnix` unhandled while the flag is set.** The only shape that
  preserves V8 behaviour exactly across V8→V9. Fail-open by construction;
  `helper_ruleset_compat.rs` forbids precisely that edit; it makes the flag
  *wider* than documented; and it breaks the probe/apply agreement that file
  keeps policy-independent, so `negotiated_abi` would report V9 while asking for
  a V8 set.
- **Additive only** — leave the write axis alone and confer on the read axes too.
  A strict superset of the chosen shape, differing only in whether a
  `--allow-write` grant carries the bit with the flag off. Rejected because it
  gives one bit two sources, where `net_rules` makes a point of being the only
  place that chooses, and it leaves the worry above live.
- **Enumerate the write set literally**, for full `net_rules` symmetry. Rejected
  for a test reason: `each_axis_confers_exactly_the_documented_set` spells its
  rights out *because* the code derives them. Have the code enumerate too and the
  test reads the same list, proving only that the code agrees with itself — which
  `guide-testing.md` forbids. The teeth that keeps over the other twelve
  bits are worth more than the symmetry.
- **A fourth `Axis` row, or a second rule pair on an existing axis.** *What is
  deliberately not a row*, below, rules out a variant whose `Grants` fields are
  meaningless, and an extra pair breaks the one-rule-per-`(axis, path)` invariant
  `helper_ruleset_tests_rules.rs` asserts.

This fixes the instance, not the class: a future write-side right still arrives
conferred on every `--allow-write` grant.
`each_axis_confers_exactly_the_documented_set` stays the tripwire, and its two
columns read identical, so a new bit on any axis shows up as the two ends of
the range disagreeing.

Narrowed once more by target kind: a non-directory intersects `from_file(abi)`.
So the real mapping is `axis × target kind × abi`, and the ABI is a negotiated
parameter, not ambient.

### The mutation check: a row flipped

Change one row, see what breaks. This is what distinguishes a table from three
lists that happen to agree.

```
round 1:  flip Axis::Write to execute: true
          ──► hard-coded assertions fail: each_axis_confers_exactly_the_documented_set,
              rights_for_narrows_a_regular_file, a_write_grant_does_not_make_files_executable

round 2:  add a fourth axis
          ──► audit_event.rs exhaustive match ← forced to notice
              Grants::paths exhaustive match  ← forced to notice
              everything else derives it
```

`rights_for`, `FsGuard::new` and `decode` took **no axis-driven edit** in either
round — which is the property the table is for.

### The CLI departs from the table, once

`--allow-write` also grants `Read`. Keyed to `axis.grants().write` rather than to
the `Write` variant, so a future write-conferring axis inherits the affordance
instead of silently missing it. The narrow, write-only form stays reachable
through `SandboxPolicy::allow_write` (#49).

## The environment allowlist

Why a sandboxed command starts with an empty environment, and why the clearing
happens in the one factory every `Command` in the crate is built by rather than at
each spawn site — with the inner stage checking what it inherited as well, so the
clearing is falsifiable. The mechanism is in `guide-sandboxing.md`; this is what
the choices were between.

### What is deliberately not a row

The environment allowlist (#98). An `Axis` is keyed by **path**, and `Grants`
answers read/write/execute about one — neither question means anything about a
variable name, so a fourth variant would have to carry a `Grants` value where all
three fields are meaningless and every `fs_rules` / `FsGuard` consumer would need
a special case to skip it. The structural precedent is the `network` and
`unix_sockets` toggles, which are policy fields with their own accessors and are
not rows either — `unix_sockets` confers a Landlock right all the same, through
`fs_rules` rather than through an axis, as `--allow-dns` does through
`resolver_paths`, which is why neither needs to be one. The environment is the
same shape again, as a list rather than a bool.

The cost of staying off the table is that nothing exhaustive *forces* a spawn
site to notice it, and a site that forgets leaks the harness's whole environment
— fail-open, where a new path consumer that ignores `Axis::ALL` grants nothing.
What closes it instead: every `Command` in the crate is built by
`spawn::command`, which narrows as it constructs, and `clippy.toml` bans
`Command::new` everywhere else under `-D warnings`. So a new spawn site does not
compile rather than failing open; the lint stands in for the exhaustive `match`.
The audit field is still hand-written.

What stands in for the compiler on the *behaviour* — that `spawn::command` narrows
at all, which the lint says nothing about — is
`sandbx-helper/tests/enforcement.rs`, which runs `/usr/bin/env` through the real
helper and reads its stdout, plus the check in `restrict_and_spawn` that refuses
an environment an earlier stage should have narrowed. The run goes through
`sandbx_helper_fixture::run`, which spawns the helper *without* clearing anything
first, so what it pins is the sandbox doing it on its own.

Without the axis, every variable the harness held crossed `fork`/`exec` verbatim
(#98):

```
$ FAKE_SECRET=leaked-abc123 sandbx sandbox-run --allow-read /usr -- /usr/bin/env | grep FAKE
FAKE_SECRET=leaked-abc123
```

and credential *injection* (#41) cannot be designed on top of an environment
that is shared in full.

### Allowlist, not denylist

A denylist of secret-looking names (`*_KEY`, `*_TOKEN`, `*_SECRET`) is wrong on
arrival and gets worse: it is a guess about naming, and it silently stops covering
the harness the first time a variable is added that does not match the pattern. An
allowlist's failure mode is the opposite and is the safe one — a variable nobody
named is dropped, and the symptom is a command that cannot find something rather
than a secret that escaped.

So `env_clear()` then re-add, rather than removing known-bad names.

### Names on the wire, values from the live environment

The policy carries `Vec<String>` of **names**. Values are read with
`std::env::var_os` at the moment the `Command` is built. One variable is set from
a constant instead; *One variable sandbx sets itself* has it.

Two reasons, and the first is the hard one. The policy crosses into the helper as
argv, and argv is not private (*Seam 2*, above): a value on the wire would be
handed to exactly the process the allowlist exists to keep it from. (This is
also why the CLI flag is `--allow-env NAME` and not `NAME=VALUE` — the latter is
#41's problem, and solving it this way would solve it wrongly. The one name
`agent-run` refuses outright is in `decision-credentials.md`.)

Second, a name is a stable thing to audit; a value is not. The audit record counts
the allowlist (`env=7`) rather than listing it, on the same basis: a name is not a
secret, but a value routinely is, and a record that spelled out names would invite
the next change to print values beside them.

A consequence worth stating: a name the harness does not hold contributes
*nothing*, rather than an empty string. Absent and empty are different to a
program that checks.

### Narrow by construction, at one site

Three `Command`s are built on the spawn path — the harness's spawn of the helper
(`helper_command`, shared by `run_to_completion` and `run_with_deadline`), the
supervisor's spawn of stage 2, and stage 2's spawn of the real program. None of
them calls `Command::new`: all go through `spawn::command`, which clears and
re-adds as it builds, so a narrowed environment is a property of every `Command`
in the crate rather than a step each site remembers.

Three alternatives were on the table, and the first two were tried and discarded.

**Clear once at the top, check at the inner stages.** Rejected **for stage 1**,
because the helper is a public entry point: any binary calling
`with_helper_dispatch` becomes a helper when handed `HELPER_FLAG`, and the
enforcement suite invokes the helper binary directly with nothing above it to have
cleared anything. A check there turns a supported invocation into a refusal, where
filtering makes it correct instead.

**Call `restrict` at each site** (#101). Not incorrect, but every call was
unfalsifiable: the sites mask each other, so any single clear could be deleted
and a later one covered for it, leaving the command's `environ` byte-identical
with no test able to tell. Hand-written obligations, each individually
unobservable, and a spawn site added later would have inherited the harness's
whole environment rather than nothing — failing *open*.

**One factory.** `spawn::command` is the only `Command::new` in production code,
and carries the only `#[allow(clippy::disallowed_methods)]` exempting it in a
crate that ships. The two exceptions spawn the sandbox rather than running inside
it, so there is nothing for the factory to narrow: `sandbx-helper-fixture`, which
starts the helper and deliberately clears nothing, for the reason given above;
and the tests that drive the built binary, which carry their own. Two properties
fall out that no amount of per-site discipline gave:

- There is one line to delete, and deleting it fails 24 enforcement tests. The
  invariant is pinned, not merely upheld.
- A new spawn site cannot forget. `clippy.toml` bans `Command::new` workspace-wide
  at `deny`, so the only way to build one is the way that narrows —
  checked by adding a bare `Command::new` elsewhere and watching the lint refuse
  to compile it.

Narrowing at the harness's and the supervisor's spawns, rather than only at the
last, is not ceremony either. A helper process lives for milliseconds, but
`/proc/<pid>/environ` is readable for all of them, and the point is that the secret
is never anywhere it does not need to be.

### Stage 2 checks as well, and refuses

Stage 2 does one more thing: before applying anything it looks at the environment
it *inherited* and refuses if the policy permits no variable of that name. The
factory is what the command relies on; this is what says whether the stage above
actually went through it. Narrowing again instead would answer the same question
with silence.

So stage 2 depends on an earlier stage having run, and the asymmetry with stage 1
is a deliberate trade rather than a derivation from reachability. Stage 2 is **not**
reachable only through stage 1: `HELPER_INNER_FLAG` is `pub` and dispatched from
argv, exactly as the enforcement suite invokes it. The honest statement is that
direct inner invocation is a test-only entry point the project is willing to see
refused, where direct stage-1 invocation is a supported one a library consumer has.
So stage 1 sanitises and stage 2 refuses.

A refusal through `SandboxError` and not an `assert!`, for the reason
`with_helper_dispatch` is exhaustive: a helper run must end by either running the
command or reporting why not, and a panic is neither — it would report a broken
harness invariant as a crash on the command's own stderr.

### `default()` passes nothing

Default-deny, matching every other axis, and matching `allow_system_executables`
as a *shape*: the library ships the strict thing and the CLI opts into the
convenience.

The trap this creates is worth naming, because it is the same one
`allow_system_executables` has, and it is sharper than it first looks. With an
empty allowlist there is no `PATH`, and a bare program name then resolves against
whichever default the lookup falls back to. There are two, and they disagree:

| Spawned by | Fallback when `PATH` is unset |
|---|---|
| `execvp` (a direct `sandbox-run -- tool`) | the C library's — `confstr(_CS_PATH)`, i.e. `/bin:/usr/bin` on glibc |
| a shell (`sandbox-run -- sh -c …`, the `bash` tool) | the shell's own compiled-in default — dash and bash both add `/usr/local/bin` and the `sbin` directories |

So it does not fail cleanly, and it does not fail consistently either:
`sandbox-run -- cat file` works, `~/.cargo/bin/tool` is not found by any route,
and `/usr/local/bin/tool` depends on whether a shell was in the way. The symptom
is `No such file or directory` with nothing to connect it to the environment. A
flat failure would at least be honest.

`Grants::policy` therefore calls `allow_standard_env()` next to
`allow_system_executables()`, for both run subcommands, and the two sit together
with one rationale: both grant what a command needs merely to *begin*, and
withholding either makes the sandbox look broken rather than strict.

`STANDARD_ENV_NAMES` is seven exact names (`PATH`, `HOME`, `TERM`, `LANG`,
`LC_ALL`, `LC_CTYPE`, `TZ`) rather than a prefix glob for `LC_*`. A glob would need
a second grammar on the helper wire, and matching logic on both sides of it, for
one convenience; a caller wanting another `LC_` variable names it.

### Skip at the gate, refuse at the seam

`allow_env` **drops** a name containing `=` or a NUL. `decode` **refuses** one
containing `=`; a NUL cannot cross argv at all.

Not an inconsistency. A caller composing a policy is in the position
`allow_system_executables` is in when a path does not exist on this system:
dropping is the conservative answer, and it is what keeps `encode`/`decode`
round-tripping — nothing `encode` can emit is something `decode` rejects. But an
argv *containing* such a name cannot have come from `encode`, so the seam is
looking at a protocol it does not speak, and this file's rule is that every decode
failure is a refusal rather than a guess.

### One variable sandbx sets itself

`--dns-over-tcp` puts `RES_OPTIONS=use-vc` in the command (why:
`decision-port-allowlist.md`). A *value*, on the axis that carries only names —
so the rule it lives under is narrow: only a compile-time constant may be
imposed, never anything read from the harness. The argv argument above does not
apply to a constant, because a value the sandboxed command can already read in
the binary it is about to exec is not a disclosure. `DNS_OVER_TCP_ENV` is the
whole table, and the policy crosses the seam carrying a valueless
`--dns-over-tcp` rather than the pair, so the wire still names no value and
*Seam 2* above stays true as written.

Two accessors keep the two halves from disagreeing. `imposed_env()` is what
`spawn::command` applies, *after* the allowlist, so a name reached both ways
arrives with the policy's value. `permits_env()` is the union of allowlist and
imposed table, and is the single predicate both `spawn::command` and stage 2's
inherited-environment check consult — because stage 2 refuses, a variable the
factory imposes and the check did not know about would kill every hinted run.
That is the one coupling here that is load-bearing rather than tidy.

Where the two names collide the library resolves it and the CLI refuses it,
which is *skip at the gate, refuse at the seam* in its other direction.
`allow_env("RES_OPTIONS")` on a hinted policy is quietly overridden, keeping the
builder total. But `--dns-over-tcp --allow-env RES_OPTIONS` is two flags
disagreeing about one variable, and honouring both would drop the operator's
value in silence — so `PolicyError::ImposedVariable`, refused as
`variable_name` refuses `NAME=VALUE`. The refusal matches against `imposed_env`
rather than the literal name, so the CLI never spells `RES_OPTIONS` and a second
imposed variable inherits the check.

### The mutation check: a name dropped

The same check the axis table's does for a table change, since
`STANDARD_ENV_NAMES` is a table of a kind:

```
drop "PATH" from STANDARD_ENV_NAMES
   ──► standard_env_carries_path                      fails   ◄── pins the name itself
       standard_env_is_the_documented_startup_set     fails   ◄── pins the whole set, in order
       the_startup_environment_is_granted_anyway      passes  ◄── derives its expectation
       audit line                                     env=6
       sandbox-run -- cat /etc/hostname               still starts   ◄── the surprise
       sandbox-run --allow-exec $dir -- mytool        ENOENT
```

The CLI test passes because it compares `policy()` against
`allow_standard_env()` rather than against seven literal names — derived from
the same source, so it moves with the mutation. That is the trap *Derived vs.
hard-coded expectations* names, and it is why
`standard_env_is_the_documented_startup_set` compares the whole set *in order*
against spelled-out names: that one is the assertion doing the work, and it is
what keeps the CLI's `--help` text naming those seven from drifting into a lie.

And `cat` still ran with no `PATH` at all, which is where the C library's
fallback above was measured rather than guessed at. The mutation's honest
symptom is the second command: a program outside `/bin:/usr/bin` is not found.
So `PATH` is load-bearing, but not all-or-nothing.

Stage 2's refusal needs a test of its own, because every path that reaches it
honestly reaches it already narrowed, where the check is trivially satisfied:
`the_inner_stage_refuses_an_unnarrowed_environment` invokes the
inner stage directly, naming the test harness as the supervisor so the liveness
check passes, and plants a variable with `Command::env`. Without it the check would
be as deletable-with-a-green-suite as the lines it exists to pin.

## A grant names an object, not a name

A policy is judged in the harness and its rules are opened in the helper. The
symlink half of that seam is shut (#205): every grant crosses already resolved,
and `open_grant` reads each descriptor back through `/proc/self/fd` and refuses
the whole run when the link names something other than what it was told to open.
A link redirected in between reads back as its target, and the run refuses.

That alone leaves substitution of one *real* directory for another at the
same name. A `rename(2)` over the vetted path — no symlink anywhere — leaves the
spelling identical, so the readback agrees and Landlock would be handed rules
over a directory the harness never vetted. The window is between the resolve in
the harness and `PathFd::new` in the helper, and reaching it needs write access
to the granted path's parent.

The comparison is about the object, not the name (#212): the harness carries
the `(dev, ino)` it vetted across the seam, the helper stats the descriptor and
refuses a mismatch, and `FsGuard` measures the matched root per access and refuses
that access as `root_replaced`. The decision this note records is not that — it
is **what the helper does with a grant that arrives with no pin**. The answer is
that it refuses, and that nothing can hand it one.

### Refusing is the only answer, so the work is making it unreachable

Accepting an unpinned grant makes the inode comparison opt-in. SECURITY.md's
claim is default-deny *at the library level, which is the level that is a
boundary*; a guarantee that holds for the CLI and lapses for a library caller is
a claim the code no longer earns, and the caller who would most benefit from the
pin is exactly the one who would not know to ask for it. So the helper refuses.

That settles the helper and leaves the real cost on the other side. `SandboxPolicy`
is public, its builders are public, and `grant` is the one place a path enters a
policy — so a refusal reaches every library embedder and the system-executable
grants `allow_system_executables` adds for itself. A refusal at run time would be
the worst version of a correct decision: the embedder learns at the refused run
what a type could have told it at `cargo build`.

So the pin travels **inside** the grant rather than beside it. A `VettedPath`
carries the resolved path and its `(dev, ino)` together, `grant` takes that
instead of a bare path, and there is no unpinned state for the helper to have a
policy about. The refusal still exists — `decode` refuses a wire grant with no
pin — but no construction path in the crate can reach it, so what an embedder
actually meets is a signature change.

### `grant` stays I/O-free

The invariant on `SandboxPolicy::grant` is not a performance note. `HelperArgs::decode`
builds a policy through `grant` too, inside the helper — the process a grant is
meant to be safe from — so resolving there would resolve against whatever the
links point at by then, and the comparison would be against the attacker's
answer. The same reasoning forbids stat'ing there.

Two producers, therefore, and the asymmetry between them is the whole design:

```
harness   vet(path)        resolve, then stat   ──►  path + (dev, ino)
helper    decode(argv)     no I/O at all        ──►  path + (dev, ino)
```

The helper's producer is crate-private and reads the pin off argv. That is not a
weaker source: argv is the harness's own, passed from stage 1 to stage 2 verbatim
and never re-encoded, and the path token has always been trusted on exactly that
basis. What the pin removes is the reliance on the *filesystem* agreeing between
the two processes, which is the only party the seam was ever exposed to.

### The pin is taken where the check is

`Grants::policy` vets each grant and then asks `reaches_owned` whether the vetted
path covers something sandbx owns. The stat belongs there, beside that check, so the
pinned object is the object the operator's refusal was evaluated against: the check
is applied to what was pinned, so the path checked is the path pinned, one value.
Resolving once for the check and again for the pin is what would let them disagree.

`allow_system_executables` pins at the site it already canonicalizes, which is
inside the library rather than in the CLI. That matters because it is the one
grant set a caller gets without going through `Grants::policy` at all, and
leaving it unpinned would reintroduce the unpinned case by the back door.

Between the vet and the encode is a window of its own, and it fails closed: a
rename there pins the object that was vetted, the helper opens the one that
replaced it, and the stat disagrees. Refusing is the right outcome and needs no
further mechanism.

After the rule is added there is no window at all. `PathBeneath` holds the
descriptor, so the kernel attaches the rule to that inode; a later rename moves
the name and not the rule.

### Three tokens per grant, not two

The wire form is a flag, a path and a pin, one triple per grant, in `Axis::ALL`
order. `decode`'s path arm refuses a grant without the pin as `BadHelperArgs` —
the same shape as "path flag with no path after it", and for the same reason:
the decoder gates enforcement, so it refuses anything it does not recognise
rather than inferring.

*Seam 2*, above, requires a wire spelling to be one `decode`
accepts by construction. A third mandatory token keeps that property; an optional
one would not, because "is this token a pin or the next flag?" is a lookahead in
the decoder, which is the thing that seam rejects.

The path token crosses through `Path::display()` and is lossy for a non-UTF-8
path. The pin neither fixes nor worsens that.

### The readback stays

The two answer different questions: the readback asks whether the name still
leads where it led, the stat asks whether the thing at the end of it is the same
thing.

In-process there is only the second question. A readback compares what was opened
against what the opener was told to open, and in `FsGuard` those are one process's
two statements about one path — the comparison would be sandbx agreeing with
itself. So the guard takes the stat alone, and `RuleTarget::Installed`'s unpinned
case one layer over is the same asymmetry read from the other end: a rule already
in a ruleset has no name left to compare.

### A rule the helper makes for itself is not pinned

`open_grant` runs in stage 2, inside the mount namespace stage 1 unshared, so a
mount made there is a mount the comparison sees. A policy bounding resolution
makes one (#145): stage 1 bind-mounts over `/etc/hosts`, `/etc/nsswitch.conf`
and `/etc/resolv.conf` before stage 2 opens the rules.

So a rule says which kind of thing it names. `RuleTarget::Granted` holds the
harness's `VettedPath`; `RuleTarget::Installed` holds the `&'static` path the
helper bind-mounted itself, after the harness judged the policy. The readback
runs on both — an installed path redirected under the bind is still a rule on
an inode sandbx did not place. The pin runs only on the first, and the reason is
not that the helper's object is trustworthy: it is that the helper has no second
answer to compare against. A pin the helper takes on a mount the helper made
compares the helper's answer with itself, and agrees whatever happened.

Pinning both at one point refuses the helper's own resolver files, the mount having
moved the inode under a name the harness had already pinned — indistinguishable from
the attack unless the two are kept apart.

This is also where the pin meets what can make a mount at all. Stage 1's
capability drop leaves stage 2 and the command no `CAP_SYS_ADMIN`, and
`BLOCKED_SYSCALLS` denies `mount` and the descriptor-based mount API
(`open_tree`, `move_mount`, `fsopen`, `fsmount`, `mount_setattr`;
`open_tree_attr` waits on libc, as `helper_seccomp_rules.rs` says). A pin that
has to survive mounts made after the vet is worth only as much as that bound.

Two orderings fall out of which crate owns which refusal, and are worth stating
because nothing maintains them. A grant refusal reaches the operator before
`UnboundedResolution` does: `unbounded_resolution` is decided in
`SandboxedCommand::command_line`, and a `SandboxPolicy` has to exist before a
`SandboxedCommand` can hold one, so `Grants::policy`'s path refusals strictly
precede it. That is the right order for diagnosis — a grant refusal sends an operator
to a path they can go and look at, a resolution refusal to flags they can read off
their own command line. And `Grants::policy` refuses `DnsGrantsBoundFile` after
the five other `Dns…` shapes, because an operator with no egress at all should
hear that first.

Write grants pay the pin twice. `Grants::policy` grants read alongside every
write-conferring axis, so a directory granted write is vetted once and pinned on
two axes, and the helper opens and stats it twice — a stat beside a resolve that
already walked every ancestor.

### What the pin costs

**A breaking change to the policy builders.** `grant`, `allow_read`,
`allow_write` and `allow_read_execute` take a `VettedPath`, so every embedder
recompiles. This is the cost that buys default-deny without a runtime refusal.

**A stat per grant, in the harness.** Beside a resolve that already walks every
ancestor, which is the expensive part.

**A stat per access, in the guard, and uncached.** `FsGuard` confirms the matched root
on every checked path, and a cached confirmation is exactly the window the measurement
exists to shrink — the cost *is* the property. One `O_PATH` open and one `fstat` on a
directory the kernel has in its dentry cache, against a `canonicalize` of the requested
path that the same check already pays. `find` and `grep` are the exception worth naming:
a walk confirms its root once and then traverses, so where the traversal runs by
path — below Linux 5.6, or under a grant naming a file — the window there is the
traversal. Above it the walk descends by `openat2` from the confirmed descriptor,
and the confirmation becomes a verdict about the operator's name rather than a
guard on the access (#230).

**A reused inode reads as the vetted object.** The pin's floor, and the one cost here
that is a limit on what the comparison can mean rather than on how it is taken. An
inode number is free once what held it is unlinked, and whether it comes back is the
filesystem's business rather than anything the pin can see. Measured on one host, not
read out of the allocators — Linux 6.18.40.1 under WSL2, ext4 on `/dev/sdd` mounted
`rw,relatime,discard,data=ordered`, and the tmpfs at `/dev/shm` with no `inode64`, by
`stat -c '%d:%i'` across three `rm -rf` plus `mkdir` repeats at one path. On ext4 the
next directory created at the same name got the number just released, all three
times; on the tmpfs the numbers came from a counter and none repeated. Neither is
specified behaviour — ext4 may return a different number and tmpfs's counter is 32-bit
and wraps — so the ext4 result is what to expect on a project tree and not a rule. So
a granted root deleted and re-created compares equal, on both layers, and is reached
although nothing the harness judged survives.

Worth separating from the attack the pin does close. A `rename(2)` substitution
puts a directory that *already exists* at the granted name, and an existing
directory cannot be holding the vetted number while the vetted object still is —
so the pin sees it. Delete-then-create is the other order, and the freed number
carries no evidence either way. Closing it for the *access* needs no third
component where the guard holds the root: the held descriptor pins the object
instead of a number naming it, so what an access reaches is what was vetted and a
reused number fools nothing (#230). Where the access goes by path — a file grant,
or a kernel without `openat2` — it fools both. Closing it for the *verdict* would
need a third component beside the pair, a creation time (`statx`'s `STATX_BTIME`,
where the filesystem reports one) or a generation number (`FS_IOC_GETVERSION`, an
ioctl), and that is not worth a filesystem-support matrix for the one case now
that the access mostly does not rest on it.

**A remount reads as a substitution.** A filesystem with no backing block device takes
an anonymous `st_dev`, allocated fresh per mount, so a grant on a network or autofs
mount that remounts mid-session begins refusing with `root_replaced`, naming a swap that
did not happen. A block-backed mount keeps its major:minor and its on-disk inode
numbers, so this is the network case and not every remount. Fail-closed and wrong about the
reason, which is the trade the pin makes: nothing distinguishes a new `st_dev` for the
same tree from a different tree without a second source of truth about the mount.

**A bind made after the vet refuses.** The readback is about spellings, so a file
bind-mounted over `/etc/hosts` reads back `/etc/hosts`; the pin is about objects,
so a bind made between the vet and the open refuses as `GrantReplaced` —
correctly, because that is the attack, and it is why the files the helper binds
itself are reached by `RuleTarget::Installed` and not by a grant.

**One pair an operator can type is refused.** `--allow-dns` alongside a grant naming
one of the three files it replaces exactly. The harness vets the host's file and the
bind substitutes sandbx's, so the pin would fail on a legitimate pair; refusing the
pair is the only fail-closed answer, because waiving the pin would have to decide the
waiver in the process that made the substitution. `--allow-read /etc` beside the flag
is unaffected — binding a file inside a directory does not change the directory's
inode — and is what the refusal tells the operator to pass. Nothing else an operator
types changes: no flag is added, no grant narrows, and a run whose granted
directories are the ones that were vetted behaves as it would without the pin.

**A granted root replaced by a symlink does not follow the link.** Re-resolving
each root at every access would make the link's target the root, reachable by
its own path. The guard holds the grant's own spelling and measures what sits at
it, and `confirm` omits `O_NOFOLLOW` — so the object it gets is the link's
target. Where that is another object the access refuses as `root_replaced` like
any other substitution; where the link names the vetted object itself the root
confirms, and the refusal comes off the resolved path leaving the granted
spelling instead. Reaching either shape needs write access to the granted root's
parent — which a run granted write on that parent has, so this is not only a
racing-attacker case.

### What a grant can be refused for

| What is wrong | Decided | Label |
|---|---|---|
| the granted spelling opens as another path | helper | `grant_redirected` |
| the object under the granted name is not the vetted one | helper | `grant_replaced` |
| the root the requested spelling names holds another object at the moment of an in-process access | guard | `root_replaced` |
| the path cannot be vetted at all — it names nothing | harness | `grant_unpinnable`, `PolicyError::UnpinnableGrant` at the flag |
| the path names a file this run's own resolver binds over | harness | `grant_bound_by_resolver`, `PolicyError::DnsGrantsBoundFile` at the flag |
| a grant arrives on the wire with no object beside it | helper, at decode | `bad_helper_args` |
| a vetted path names nothing by the time the helper opens it | helper | `landlock`, carrying the kernel's `ENOENT` unchanged |

The last is the unlink-after-vet window, and it is the reason `VettedPath::from_wire`
is testable without racing: it is the one producer that can build a vetted path naming
nothing. The other two shapes of that window are the first two rows — unlinked and
replaced is `grant_replaced`, unlinked and symlinked is `grant_redirected`.

`guard` is not `harness` under another name, though both run in sandbx's own process.
`harness` rows are decided once, while a policy is being built, and refuse the grant —
there is no run. A `guard` row is decided per access, against a policy already built,
and refuses *that access* and nothing else: the grant stands, and the next call measures
again. And only `helper` rows cross the audit channel, which is why `root_replaced` is
not in `HelperRefusal` — see `decision-helper-audit-channel.md`.

### What was rejected for an unpinned grant

**Accepting an unpinned grant.** It makes a stated guarantee conditional on the
caller asking for it (*Refusing is the only answer*, above).

**Refusing at run time, with the pin beside the grant.** Identical security,
worse failure. A `SandboxPolicy` field next to the paths can be left unset, so
the embedder's first signal is a refused run rather than a compile error, and
`allow_system_executables` would need its own arm to avoid refusing itself.

**Inheriting the harness's `O_PATH` descriptor through the exec.** The cleaner
close, and the one that re-resolves nothing helper-side at all: no pin to carry,
no third token, no comparison to get wrong. Receiving an inherited descriptor
needs `from_raw_fd` and passing one needs `pre_exec`, both `unsafe`, against the
workspace-wide `unsafe_code = "forbid"` that no crate overrides. Rejected on the
lint, not on the design, and it is the shape to return to if the lint ever gains
a carve-out.

**Treating the stat as equally blocked.** #212's own text reads as though the
lint prices both remedies out. It does not: `nix` is already a `sandbx-core`
dependency with the `fs` feature, so `fstat` over an `AsFd` is safe and in-tree,
and `fs::metadata` on `/proc/self/fd/<n>` is a second route with no new
dependency, resolving the magic link to the inode the descriptor holds rather
than by name. Only the descriptor-inheritance route is lint-blocked.

**Resolving in the helper instead.** The oldest rejected shape, recorded on
`grant` and restated here because the pin makes it tempting a second time: with a
stat available, "just canonicalize helper-side and compare" looks like it needs
no seam change. It resolves in the process the grant is meant to be safe from.

## What the harness does when a grant covers something it owns

Three issues asked one question. `--allow-write` over the session root lets one
turn choose what the next turn is told it said (#173). `--allow-read ~/.config`
hands a tool the credential file and the provider key in it (#184). `--allow-read
/proc` reaches `/proc/<harness-pid>/environ`, so an operator who *exported* the
key handed it over without naming it to `--allow-env` at all (#192). In each the
operator granted a tree, and the tree held something that is sandbx's rather than
the project's.

The question is not which paths are sensitive. It is what a harness may do about
a grant it was handed. `decision-credentials.md` sets the rule it has to be
answered under; this is where it is answered, and the answer is two mechanisms
rather than one. The two on-disk roots are refused. The procfs route is closed
by sandbx hiding its own process instead, because refusing `/proc` would cost
`sandbox-run` a legitimate use for a hazard that is not about a path at all.

### Subtraction was never available

The shape that looks right first — grant the tree, carve out the file — does not
exist. Landlock composes rules by union and has no exclusion form, so a ruleset
cannot say "everything under `$HOME` except one path"; adding the narrower rule
adds access rather than removing it. `vetted_root` in `sandbx-grants` records
the same finding where it rejected a carve-out for the running binary, and
`SandboxPolicy` is grants-only for the same reason: there is no subtracting type
to put a carve-out on.

Nor can the grant be decomposed into the siblings of the owned path. A tree is
not a fixed set — `~/.config` gains a directory the day after the run — so a
decomposed grant is narrower than what was typed in a way that drifts, and the
operator who typed `--allow-read ~/.config` would get a policy nobody wrote.

What is left is to refuse, or to take the owned thing out of reach by some route
other than the policy. Both are used here, one each.

### Both subcommands, because a refusal is all it may be

`decision-credentials.md` fixes the rule: **the two subcommands may differ
by a refusal, never by a policy**, and the test of a refusal is that it is
decidable from argv. `agent-run` can refuse `--allow-env ANTHROPIC_API_KEY`
one-sidedly because the name is matched against a constant.

A path refusal is not like that. Whether `--allow-read ~` reaches the session
directory is answered by deriving both paths and comparing them, and a comparison
one subcommand acts on and the other ignores is two policies from one set of
flags. So this refusal applies to both subcommands or to neither — and it applies
to both, which keeps `the_policy_matches_what_sandbox_run_derives` green by
construction rather than by exemption: neither subcommand derives a policy at
all.

That is also why it lives in `Grants::policy`, which the same document rejected
as a home for the credential check. The rejection was about *attribution*:
`Grants` does not know which subcommand is asking, so it cannot refuse for one of
them. A rule that holds for both needs no attribution, and `Grants` is the one
place argv becomes a `SandboxPolicy` — flattened into both run subcommands, so
they cannot drift apart.

The operator keeps an escape that is not a flag: `sandbox-run` under a different
`$HOME`, or `XDG_STATE_HOME` pointed elsewhere, moves what sandbx owns and the
refusal moves with it. That is the honest form of an override — it says where the
state went, instead of leaving sandbx holding state inside a tree it just handed
away.

### Either direction, and both spellings

A Landlock right covers a subtree, so containment has to be tested both ways
round. A grant *above* the session directory hands over every transcript; a grant
naming one transcript inside it hands over that history, which is the file whose
contents become what the model is told it said. `reaches_owned` therefore runs
`starts_with` in both directions, on components rather than bytes, so a directory
merely spelled like an owned one — `~/.config/sandbx-notes` — still derives.

Nothing requires a grant to be absolute. A purely lexical comparison would
therefore miss `--allow-read .` from `$HOME`, and miss the host where `/home`
links to `/var/home` — Fedora Silverblue — where one spelling would be refused
and the other would not. `resolved` closes both by canonicalizing the deepest
ancestor that exists and re-joining what is left, applied to each side of the
comparison. The deepest
*existing* ancestor and not the whole path, because `canonicalize` needs every
component to exist and a credential nobody has stored yet does not.

A relative grant is joined to the working directory before any of that, which is
what it is vetted and granted as too. Resolving it ancestor by ancestor is not
enough on its own: the walk bottoms out at the empty path, so a relative grant
whose *first* component does not exist yet — `--allow-write sandbx` from
`~/.local/state`, with no transcript saved — would stay relative and match no
absolute owned path. That is the one spelling in which existence could still have
decided the verdict, and it is the spelling `--session` creates during the very
run the policy was derived for.

A working directory that cannot be read refuses the relative grant rather than
standing in as nothing, which would leave it matching no owned path (#203). An
absolute grant needs no working directory and is not refused for one. So an
invocation that typed its own flags still never depends on `HOME`, but it
depends on `getcwd` for a relative one, and the refusal says to write the grant
absolute rather than advising the path flags it was already given.

Joining the cwd is therefore a step of its own — `absolute`, which the flag route
calls and the derived route does not, over a `resolved` that is total. The cwd
arrives as an argument rather than off the process: a direction that fails only
on a deleted directory is one no test can pin.

What `resolved` returns is a `ResolvedPath`, and `vetted_root` and `reaches_owned`
take that type rather than a `PathBuf` — so each states the precondition in its
signature, rather than leaving the spellings above to the callers happening to
comply (#248). `resolved` is one producer; the other is a `VettedPath`,
canonical already, converted with no I/O, which is how a grant is judged as the
path it pins.

### It does not ask whether anything is stored there

The refusal fires on a host with no transcript and no key, exactly as #41's
refusal fires with the variable unset. Three reasons, and the first is the one
that would bite:

An existence-sensitive refusal is a race. `agent-run --session` creates the
transcript during the run the policy was derived for, so a check against the
filesystem would answer "nothing there" and then put something there. The same
run would be refused on its second invocation and not its first.

The second is testability, the reason `decision-credentials.md` gives for
the by-name refusal: a verdict keyed on what is on disk this minute is a verdict
no test can pin without building the state it is testing for. The third is that
the same argv then gets the same answer on every host, so an operator reporting a
refusal reports something anybody can reproduce.

### There is no exact-path hatch

`--allow-read ~/.config/sandbx/credentials.toml` is refused, not honoured as the
narrowest possible form of the request. Naming the file *is* the request the
refusal exists for: the hazard is a tool reading the key, and a flag that names
the key's file is the shortest way to that. A hatch at the exact path would also
be a hatch for an injected flag in any wrapper script that builds an argv, with
the one spelling that reads most like deliberate care.

### The derived default is the same hazard by another route

A no-flag run from inside the session directory derives read and write over the
working directory, and the working directory is the history. Every other
derived-root refusal sits inside `if !self.paths_given()`, so it guards only the
default, and the per-grant check guards only the flags. So `vetted_root` carries
the same arm as the per-grant loop, and one rule covers both — the refusal is
about what a grant reaches, not about how the grant was spelled.

One rule, two messages, and they are different errors on purpose. The derived
route refused nothing the operator typed, so it reads like its neighbours —
"refusing to derive a policy from …" — and ends on the shared advice to pass the
path flags. The flag route cannot end there: advising `--allow-read PATH` to an
operator whose `--allow-read` was just refused says nothing, so it says what to
change about the path instead.

### #192 is a different mechanism, not more of this

An exported key is not on a path sandbx owns. It is in sandbx's own memory and
`environ`, which procfs publishes to every process running as the same uid; the
harness is not sandboxed, and `/proc` is the host's.

Refusing `/proc` as a path was available and is disqualified twice over. It would
be a refusal by name, which `SECURITY.md` declines for `/etc`, `/var`, `/proc`
and `/sys` on the grounds that depth is not sensitivity and a list of dangerous
directories has a silent first omission. And it would break `sandbox-run`: a
command reading `/proc/self/status` is ordinary, the operator chose it, and the
key it would be protected from is one the operator exported for sandbx to spend.

So sandbx conceals its own process instead. `conceal_process_state` clears
`PR_SET_DUMPABLE` at startup, which makes the kernel reparent `/proc/<pid>/` to
root; `environ`, `mem`, `maps` and `fd/` then fail `__ptrace_may_access` for a
same-uid reader. No policy changes, both subcommands behave identically, and
`sandbox-run --allow-read /proc` keeps working for everything except sandbx's own
entry.

It costs the two things the flag was protecting: no core dump of the harness, and
no same-uid debugger attach to it, so `gdb -p` and `strace -p` against a running
sandbx are refused. A failure to set it is a refusal rather than a degradation,
unlike the capability bounding set — there the bit cannot be spent on any host,
here the key is exposed on the host where the call failed.

The call sits just after `Cli::parse`, which is what lets the refusal exit with
the subcommand's own failure code: `auth status` spends 1 on "no key anywhere",
so a refusal there has to be 2 or a script reads it as an absence. Parsing argv
exposes nothing, and nothing has been spawned yet either way — what the flag has
to precede is the first sandboxed command, not the first line of `main`.

The supervisor does not set it, and `helper_hardening.rs` says why: the kernel
resets dumpable on every `execve` of an ordinary binary, so it would cover only
the pre-exec window. Stage 2 never `exec`s and clears it on itself, because the
command shares its Landlock domain. That same reset is what keeps the sandboxed
command unaffected, which is correct — its `environ` holds only what
`--allow-env` named.

What this does not close: every *other* same-uid process's `environ` is still
reachable through a `/proc` grant, `/proc/<harness-pid>/cmdline` stays readable,
and the supervisor's own entry is not concealed, which is what the audit
channel's `/proc/<helper-pid>/fd/0` exposure rides on. "Do not grant `/proc`"
stays.

### What the refusal costs

`--allow-read ~` and `--allow-read /` are refused on every host, with no key
stored and no session saved, because both roots derive under `$HOME`. Those two
flags are the ones an operator reaches for when a command needs more than the
project tree, so this is the refusal most likely to be met as a regression. The
message names the grant, the owned path inside it, and what sandbx keeps there;
the answer is to grant the trees the command needs.

Nothing else narrows. A grant over a project tree, a scratch directory, `/usr`,
`/tmp` or `/etc` derives as it would without the check, and no subcommand gains a
policy difference.

### What was rejected for an owned path

**A warning instead of a refusal.** Printing "this hands over your key" and
continuing is the fail-open shape `decision-credentials.md` rejects twice, for
the keyring and for a tool's credential. The operator who granted the tree by
mistake is the one who will not read the line.

**Stripping the owned path out of the grant.** Silently narrowing derives a
different policy from the same flags, which is the divergence
`the_policy_matches_what_sandbox_run_derives` exists to catch, and the symptom is
a tool failing on a path the operator was told it could read.

**Refusing on `agent-run` only.** The hazard is worst there, but the route is not
decidable from argv, so a one-sided answer would be a policy difference and the
rule forbids it.

**An `--allow-owned-paths` override.** A flag that unlocks the one grant the
refusal exists for would be typed by exactly the operator the refusal is for, and
read as a permission rather than a hazard. Moving `$HOME` or `XDG_STATE_HOME`
already moves what sandbx owns, which is the same power stated honestly.

### The mutation check: an owned path granted

Delete the `reaches_owned` check from the per-grant loop in `Grants::policy`:

```
delete the if in the per-grant loop
   ──► a_grant_reaching_an_owned_path_is_refused_on_both   fails
       naming_the_credential_file_itself_is_refused        fails
       a_grant_above_an_owned_root_is_refused              passes  ◄── tests the helper
       a_grant_inside_an_owned_root_is_refused             passes  ◄── tests the helper
       a_root_inside_an_owned_path_is_refused              passes  ◄── the other arm
       the_policy_matches_what_sandbox_run_derives         passes  ◄── no divergence to see
```

The unit tests over `reaches_owned` keep passing, because the helper still
answers correctly — what was deleted is the one call that acts on its answer. The
two spawned cases in `cwd_policy.rs` are the only ones that fail, which is why
they exist, and `cargo test` stops at the first failing binary so they have to be
run with `--test cwd_policy` to be seen.

Delete the arm in `vetted_root` instead and `a_root_inside_an_owned_path_is_refused`
is the only failure: the two routes are covered separately on purpose.
