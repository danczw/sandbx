# Module layout

A module is read whole. Its length is the cost of holding it in your head before
you can safely edit any line of it — so the figure that matters is the code, not
the file. A thoroughly tested module is a long file and a short module.

Count the lines above the first `#[cfg(test)]`.

## Budget

| Thing | Budget |
|---|---|
| module (non-test lines) | 400 |
| + one irreducible thing: a state machine, a syscall sequence | say why, in the module's `//!` |
| file total, tests included | no budget |

The ceiling is headroom, not a target. Split when a module has two reasons to
change, not when it crosses a number: `helper/` is carved into `seccomp`,
`hardening` and `ruleset` by enforcement mechanism, and a module failing that
test is over budget well under the ceiling. One that reaches the ceiling doing a
single thing stays whole — splitting it trades one long file for several that
have to be read together.

## Where tests live

Inline, in the same file, by default:

```rust
#[cfg(test)]
mod tests {
    use super::*;
}
```

Move them to `foo/tests.rs` when the file passes roughly a thousand lines, or the
tests outweigh the code by more than about three to one. `foo.rs` may own a
`foo/` directory for its submodules: the file does not become `foo/mod.rs` and
needs no `#[path]`. Split again into `foo/tests/`, one file per topic, once the
moved tests are themselves over budget — `wire/tests/` and
`helper/ruleset/tests/` already do.

Either way the tests stay compiled into the crate, which is the point: they reach
private items. `crates/*/tests/` is a separate crate and sees only the public
surface, so a unit test cannot move there without widening the API to suit it.
Never make that trade — a module is private so that its internals are not an API,
and keeping its tests inside the crate is what lets it stay that way.

| Test | Home |
|---|---|
| touches a private or `pub(crate)` item | inline, or `foo/tests.rs` |
| drives the crate's public API | `crates/<crate>/tests/<topic>.rs` |
| needs a sandbox-capable kernel | `crates/sandbx-core/tests/`, behind `sandbox-integration` |

## Measuring

```sh
for f in $(find crates -name '*.rs' -path '*/src/*' -not -path '*/tests/*'); do
  cut=$(grep -n '#\[cfg(test)\]' "$f" | head -1 | cut -d: -f1)
  printf '%5d  %s\n' "$([ -n "$cut" ] && echo $((cut - 1)) || wc -l < "$f")" "$f"
done | sort -rn | head -12
```

A hit is a judgement call, not a failure: read the module and decide whether it
has two jobs. Do not turn this into a lint — the number needs a human to
interpret it, and a cap on raw file length fires soonest where length means least.

Modules with no inline tests have no slack: their whole length is budget, and
splitting one moves code rather than tests, so it carries behavioural risk that
relocating a test module does not.
