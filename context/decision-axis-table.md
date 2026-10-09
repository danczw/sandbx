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
| `sandbx-cli/src/grants.rs` | three flag blocks | loop + exhaustive `match` |

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

The cost of staying off the table was that nothing *forced* a site to notice it.
While the four `env::restrict` calls were hand-written, a fifth spawn site added
later would have **leaked the harness's whole environment** — not inherited
nothing — which failed open, the one place this was weaker than the path axes,
where a new consumer that ignores `Axis::ALL` grants nothing instead.

Closed since, by a different mechanism than the table: every `Command` in the
crate is built by `spawn::command`, which narrows as it constructs, and
`clippy.toml` bans `Command::new` everywhere else under `-D warnings`. So a new
spawn site does not compile rather than failing open. The lint stands in for the
exhaustive `match` the environment does not get by being a row. The audit field is
still hand-written.

What stands in for the compiler on the *behaviour* — that `spawn::command` narrows
at all, which the lint says nothing about — is `tests/enforcement.rs`, which runs
`/usr/bin/env` through the real helper and reads its stdout, plus the check in
`restrict_and_exec` that refuses an environment an earlier stage should have
narrowed. One site to delete, 24 failures when it goes. See
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

It runs the other way on the write axis, which is the cost of the second line and
not an oversight. `write` is the complement of the read set within `from_all`, so
a new right the kernel does not put in `from_read` is *conferred* by
`allow_write` automatically — permitted until someone notices, on the widest axis
there is. Subtracting the whole read set rather than `Execute` alone is what buys
it: one bit less and a write grant confers read at the kernel that `FsGuard`
refuses, leaving the write-only drop directory readable (`rights_for`'s `///`).
`ResolveUnix` is the worked example rather than a hypothetical — it arrived at
ABI V9 and joined the write set, which is why
`each_axis_confers_exactly_the_documented_set` pins the write axis at both ends
of the range and the two sets differ by exactly that bit. It also reaches a flag:
on a V9 kernel (Linux 7.1, `LATEST_ABI`) `--allow-unix-sockets` lifts the seccomp
denial on `socket(AF_UNIX, …)` and Landlock then refuses the `connect` for any
pathname socket outside a write grant, so a flag documented as all-or-nothing
acquires a path condition with no line edited, and a command that works today
fails on a newer kernel with the same flags (#259).

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
          ──► audit.rs exhaustive match       ← forced to notice
              Grants::paths exhaustive match  ← forced to notice
              everything else derives it
```

Whole suite green throughout, with `rights_for`, `FsGuard::new` and `decode`
taking **no axis-driven edit** — which is the property the table was for.

## The CLI departs from the table, once

`--allow-write` also grants `Read`. Keyed to `axis.grants().write` rather than to
the `Write` variant, so a future write-conferring axis inherits the affordance
instead of silently missing it. The narrow, write-only form stays reachable
through `SandboxPolicy::allow_write` (#49).
