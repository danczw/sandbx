# Testing

What a test has to assert to be worth having, where it lives, and the two house rules
the Google style guide leaves to the project. `decision-google-style.md` is why the
guide governs everything else here, and its grace rule is why existing tests may not
yet match the layout below.

## The framework is plain `#[test]`

`#[test]`, and `#[tokio::test]` where the body must await. No test framework, no
fixture macro, no parameterised-case crate. A table-driven case is a `for` loop over
an array literal in the test body, which `cargo test` reports as one test — so the
loop asserts *which* element failed, or a failure names nothing.

## Where a test lives

A unit test is a sibling file, declared from the module it tests:

```rust
#[cfg(test)]
#[path = "foo_tests.rs"]
mod tests;
```

It stays compiled into the crate, which is the point: it reaches private items.
`crates/*/tests/` is a separate crate and sees only the public surface, so a unit test
cannot move there without widening the API to suit it. **Never make that trade** — a
module is private so that its internals are not an API, and keeping its tests inside
the crate is what lets it stay that way.

| Test | Home |
|---|---|
| touches a private or `pub(crate)` item | `foo_tests.rs`, beside `foo.rs` |
| drives the crate's public API | `crates/<crate>/tests/<topic>.rs` |
| needs a sandbox-capable kernel | `crates/sandbx-helper/tests/`, behind `sandbox-integration` |

The sibling is named after the module, except at a crate root, where the file
name says nothing about what it holds. A `lib.rs` takes the crate's own name —
`sandbx-compact`'s is `compact_tests.rs` — and a `main.rs` takes
`main_tests.rs`. `sandbx-cli` is why the two differ: it has both roots, so
naming either after the crate would leave the other with no name to take.

`use super::*` in that sibling module is a recorded departure from the guide, not an
oversight; `decision-google-style.md` says why.

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
  `helper_seccomp_tests_denylist.rs` asserts `!BLOCKED_SYSCALLS.is_empty()` with
  "the denylist is empty, so this test is vacuous", and
  `helper_ruleset_tests_rules.rs` asserts the handled set moves with the ABI
  rather than letting the agreement above it hold trivially. A loop over an empty
  set passes; so does an agreement between two things neither of which was
  computed.
- **Pair the negative with evidence the mechanism ran** — the stderr it writes,
  the exit code it chose, the audit record it emits. `!status.success()` alone
  cannot tell a denial from a helper that never started.

Hard-code the expected value rather than reading it off the thing under test.
`tools_bash.rs`'s `NOT_RETRYABLE` and `guide-tools.md`'s risk-level test both
say why: read off the source, the assertion only proves it agrees with itself,
and a reclassification passes.

A set of negative cases also needs one positive per mechanism, or the mechanism's
total absence is indistinguishable from it working. `enforcement.rs` grants
`/bin/touch` everything it needs for exactly that reason — without the grant the
exec itself would be denied and the test would stay green for the wrong reason.

## Every assert carries a message

Every `assert!`, `assert_eq!` and `assert_ne!` takes a message, and the message must
**add information** — why the property holds, or which values were involved. One that
restates the condition costs a line and buys nothing, because the condition is already
printed above it:

```rust
// Nothing: the panic already shows `left`, `right` and the expression.
assert_eq!(abi, V5, "abi should equal V5");

// Something: says what breaks, so a failure needs no second file open.
assert_eq!(abi, V5, "the negotiated ABI is the floor every rule below assumes");
```

A vacuity assert (above) is the case where the message is the whole point — it names
the condition under which the test around it proves nothing.

## Test names

Fifty characters, and that is a ceiling rather than a target. Tests get a longer
allowance than other items because **the name is what a failure prints**: `cargo test`
shows it without the `///`, so what the test asserts has to be legible from the
failure line alone. Past about fifty characters it stops being scannable in a list of
four hundred.

Renaming a test can break a prose reference. `context/*.md` cites test names as
the evidence for a claim, and so does a `//!` — the mutation index on
`sandbx-grants`' `root::tests` is a claim-to-test-name map outright. Grep
`context/` and `crates/` for the old name before considering the rename done.
