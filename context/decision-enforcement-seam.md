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
                            check_read              ──► resolved path  ◄── ls only
```

Tools hold **handles, not paths**. That is what closes the TOCTOU window: if the
leaf became a symlink between check and use, the open fails. `ls` is the one
exception, because `read_dir` has no handle form.

### A refusal says nothing, except inside a grant

`canonicalize` fails differently for a missing path (ENOENT), an unreadable
parent (EACCES) and a path that resolves out of bounds. Handing the difference
back makes the guard a filesystem oracle, and the refusal travels inside a
`tool_result` — so a prompt-injected model can map the host with it. Every
refusal outside the roots is therefore the same refusal.

`conceal_unless_granted` is the one exception, and it has a single rule: the
nearest ancestor that *does* resolve decides. Inside a granted root the caller
could enumerate the directory anyway, so absence there is honest, and it is
`SandboxError::NotFound` — gated on `ErrorKind::NotFound`, because a `000`
directory inside a grant is still a refusal and keeps `Unresolvable`. Absence is
no verdict, so it emits no audit record, and `sandbx-tools` maps it to
`ToolError::Failed` rather than `Denied` (#180).

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
| 5 | per-endpoint egress | #42 — a TCP port allowlist, which is all the kernel can match on. Per-host is not enforced and needs a userspace proxy (#145) |

53 real-kernel enforcement tests, split by what enforces them: 39 in
`tests/enforcement.rs` for paths and grants, 8 in `tests/enforcement_syscalls.rs`
for the calls Landlock cannot express, 6 in `tests/enforcement_network.rs` for
the ports it does. All three files are
`#![cfg(all(feature = "sandbox-integration", target_os = "linux"))]`, so the
count is unconditional — all 53 run or none of the files compiles, and
`cargo test` reports `0 ignored`. Nothing checks this number against the files.
