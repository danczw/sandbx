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

## Seam 2 — argv, into the helper process

The policy crosses *two* process boundaries as argv:

```
sandbx ──argv──► helper stage 1 (supervisor) ──argv verbatim──► stage 2 ──► apply()
```

| | |
|---|---|
| Shape | `HelperArgs { policy, program, args }`, `encode` / `decode` |
| Path flags | `--ro` / `--rw` / `--rx`, from the single `path_flag(axis)` match |
| Other flags | `--allow-network`, `--allow-unix-sockets`, `--env NAME` (repeatable), `--` separator |
| Why argv | the environment is now cleared at every stage (#98), so it cannot carry the policy — argv is the only channel left that survives the re-exec. It is not *private*: the command reads its own `/proc/self/cmdline`, so the rule is that argv carries variable **names**, never values |
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
```

Both live in `helper/ruleset/rights.rs`. ABI negotiation and the verdict live in
`helper/ruleset/compat.rs`; the syscall list in `helper/seccomp.rs`; `apply` in
`helper/mod.rs`.

`abi` is a **parameter**, not ambient — that is what makes the mapping
kernel-independent and testable at both ends of the range.

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
| `each_axis_confers_exactly_the_documented_set` | | ✓ `make_bitflags!`, both ABI ends |
| `rights_for_narrows_a_regular_file` | | ✓ `file_legal` spelled out |
| audit counts | | ✓ exhaustive `match` |
| `SandboxRun::paths` | | ✓ exhaustive `match` |

The hard-coded rows are the ones that would fail if `Axis::Write` were flipped to
`execute: true`. The two exhaustive matches are what make a *new* axis a build
failure — not the length of `Axis::ALL`, which nothing needs at compile time.

## #52's five items

| # | Item | State |
|---|---|---|
| 1 | `fs_rules` untestable without root | **done** — split out, asserted with no kernel |
| 2 | nothing asserted the axis→rights mapping | **done** |
| 3 | nothing pinned the *exact* right set | **done** (#74) — `each_axis_confers_exactly_the_documented_set` pins every axis's whole `BitFlags` at `BASELINE_ABI` and `LATEST_ABI`, and asserts a row exists per `Axis::ALL` |
| 4 | partial enforcement accepted | **done** (#76) — `enforcement_verdict` refuses it |
| 5 | per-endpoint egress | **open** (#42) |

38 real-kernel enforcement tests in `tests/enforcement.rs`.
