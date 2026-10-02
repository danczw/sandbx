# The axis table

Why filesystem policy has one table and five consumers instead of five parallel
lists. The current derived-vs-forced breakdown lives in `decision-enforcement-seam.md`;
this is how it got that way and how it was checked.

## The table

```rust
pub enum Axis { Read, Write, ReadExecute }          // closed. No dyn, no #[non_exhaustive]
pub struct Grants { read: bool, write: bool, execute: bool }

Axis::Read        => (true,  false, false)
Axis::Write       => (false, true,  false)
Axis::ReadExecute => (true,  false, true )
```

## Before and after

| Site | Before | After |
|---|---|---|
| `helper/ruleset/rights.rs` | three `if allow_* {}` arms | loop over `Axis::ALL`, rights from `grants()` |
| `fs_guard.rs` | two hand-built path lists | destructure `grants()` into readable/writable |
| `helper_args.rs` | three flag spellings, twice (encode + decode) | one `path_flag` match, `axis_for` as reverse lookup |
| `audit.rs` | three counted fields, hand-maintained | loop + exhaustive `match` |
| `sandbx-cli/src/lib.rs` | three flag blocks | loop + exhaustive `match` |

Two sites cannot derive their answer and are **forced** instead — `tracing` needs
static field names, and clap needs per-flag `--help` text. Both pair the loop
with an exhaustive `match`, so a new axis is a build failure rather than a
silently missing grant.

> Not the *length* of `Axis::ALL`. An earlier design pinned the audit record to
> fixed-arity destructuring for exactly that reason; it was reverted, and nothing
> now needs the array's length at compile time. The exhaustive matches are the
> whole mechanism.

## What is deliberately not a row

The environment allowlist (#98). An `Axis` is keyed by **path**, and `Grants`
answers read/write/execute about one — neither question means anything about a
variable name, so a fourth variant would have to carry a `Grants` value where all
three fields are meaningless and every `fs_rules` / `FsGuard` consumer would need
a special case to skip it. The structural precedent is the `network` and
`unix_sockets` toggles, which are policy fields with their own accessors and are
not rows either; the environment is the same shape, as a list rather than a bool.

The cost of staying off the table is that nothing *forces* a site to notice it.
The four `env::restrict` calls and the audit field are hand-written, and a fifth
spawn site added later would **leak the harness's whole environment** — not
inherit nothing. It fails open, which is the one place this change is weaker than
the path axes, where a new consumer that ignores `Axis::ALL` grants nothing
instead.

What stands in for the compiler is `tests/enforcement.rs`, which runs
`/usr/bin/env` through the real helper and reads its stdout, so a stage that stops
clearing is a test failure rather than a quiet regression. That covers the stages
that exist; it cannot cover a stage nobody has written yet. See
`decision-environment-allowlist.md`.

## Why the rights are subtractions

```
read  = from_read(abi) & !Execute
write = from_all(abi)  & !from_read(abi)
exec  = read | Execute        ← so read | Execute == from_read(abi)
```

Stated as what each axis *removes* from the kernel's own sets, not as an
enumeration of what it grants. A right added by a future ABI lands in `from_all`
and is denied by `allow_read` automatically, rather than being permitted until
someone notices.

Narrowed once more by target kind: a non-directory intersects `from_file(abi)`.
So the real mapping is `axis × target_is_dir × abi`, and the ABI is a negotiated
parameter, not ambient.

## The mutation check

Change one row, see what breaks. This is what distinguishes a table from three
lists that happen to agree.

```
round 1:  flip Axis::Write to execute: true
          ──► hard-coded assertions fail: each_axis_confers_exactly_the_documented_set,
              rights_for_narrows_a_regular_file, a_write_grant_does_not_make_files_executable

round 2:  add a fourth axis
          ──► audit.rs exhaustive match        ← forced to notice
              SandboxRun::paths exhaustive match ← forced to notice
              everything else derives it
```

Whole suite green throughout, with `rights_for`, `FsGuard::new` and `decode`
taking **no axis-driven edit** — which is the property the table was for.

## The CLI departs from the table, once

`--allow-write` also grants `Read`. Keyed to `axis.grants().write` rather than to
the `Write` variant, so a future write-conferring axis inherits the affordance
instead of silently missing it. The narrow, write-only form stays reachable
through `SandboxPolicy::allow_write` (#49).
