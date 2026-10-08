# Module layout

A module is read whole. Its length is the cost of holding it in your head before
you can safely edit any line of it — so the figure that matters is the code, not
the file. A thoroughly tested module is a long file and a short module.

Count the lines above the inline `mod tests` block. A module whose tests were
moved to `foo/tests.rs` or `foo/tests/` counts whole — what it declares is a
line, not a suite.

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
moved tests are themselves over budget — `wire/tests/`, `helper/ruleset/tests/`
and `helper/seccomp/tests/` already do.

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

## What a test has to assert to assert anything

A test pins a defect only when the defect's answer differs from the answer the
test expects. So a test expecting a refusal catches nothing whose failure mode is
to refuse, and most of this repo's mechanisms fail that way: a ruleset the kernel
would not take, a filter that did not install, a fixture whose directory dropped
before the assertion read it, a comparison that fell through. Each of those denies
everything, and a suite of denials stays green through all of them. Mirroring a
positive case to get a negative one buys nothing for the same reason — the mirror
expects the answer the break already gives.

Two things make a negative test real, and the stronger one is executable:

- **Assert the fixture is not vacuous before relying on it.**
  `helper/seccomp/tests/denylist.rs` asserts `!BLOCKED_SYSCALLS.is_empty()` with
  "the denylist is empty, so this test is vacuous", and
  `helper/ruleset/tests/rules.rs` asserts the handled set moves with the ABI
  rather than letting the agreement above it hold trivially. A loop over an empty
  set passes; so does an agreement between two things neither of which was
  computed.
- **Pair the negative with evidence the mechanism ran** — the stderr it writes,
  the exit code it chose, the audit record it emits. `!status.success()` alone
  cannot tell a denial from a helper that never started.

Hard-code the expected value rather than reading it off the thing under test.
`tools/bash.rs`'s `NOT_RETRYABLE` and `guide-tools.md`'s risk-level test both say
why: read off the source, the assertion only proves it agrees with itself, and a
reclassification passes.

A set of negative cases also needs one positive per mechanism, or the mechanism's
total absence is indistinguishable from it working. `enforcement.rs` grants
`/bin/touch` everything it needs for exactly that reason — without the grant the
exec itself would be denied and the test would stay green for the wrong reason.

## Measuring

```sh
for f in $(find crates -name '*.rs' -path '*/src/*' \
             -not -path '*/tests/*' -not -name 'tests.rs'); do
  cut=$(grep -nE '^(pub(\([^)]+\))? )?mod tests \{$' "$f" | head -1 | cut -d: -f1)
  printf '%5d  %s\n' "$([ -n "$cut" ] && echo $((cut - 2)) || wc -l < "$f")" "$f"
done | sort -rn | head -12
```

It anchors on the block, not on `#[cfg(test)]`, because that attribute is not
where the tests start. `#[cfg(test)] mod tests;` sits with the other `mod` lines
at the top of a file, so cutting there reported `helper/ruleset/mod.rs` as 11
lines; a `#[cfg(test)]` named inside a doc comment cut `anthropic.rs` to 37. Both
under-reported, which is the direction that lets a module over budget go unseen.

The visibility is optional because `pub(super) mod tests {` is house style where a
sibling module imports the helpers. A pattern that misses it falls back to `wc -l`
and reports a compliant module as its whole file length — an invented overrun,
which is the other direction and costs a reader the whole file. `[^)]+` rather than
`[a-z]+` so `pub(in crate::path)` matches too — nothing spells it that way today,
and a visibility the pattern does not know is the failure this command has had.

Read the file before you believe the figure. A count that contradicts the module in
front of you is the command being wrong about that module's shape, not the module
being over: there is no second method to break the tie, only the file.

A hit is a judgement call, not a failure: read the module and decide whether it
has two jobs. Do not turn this into a lint — the number needs a human to
interpret it, and a cap on raw file length fires soonest where length means least.

Modules with no inline tests have no slack: their whole length is budget, and
splitting one moves code rather than tests, so it carries behavioural risk that
relocating a test module does not.
