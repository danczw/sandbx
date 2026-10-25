# Decision: the Google Rust style guide, and where sandbx departs from it

Why the workspace follows [Google's Rust style
guide](https://google.github.io/styleguide/rustguide.html) rather than a house style
of its own, which of its rules are skipped, and the departures that are deliberate.
The guide is the mechanism; this is what the choices were between, and what guards
each departure against being re-proposed as an oversight.

The rules marked *(Chromium)* are adopted — small crates, a flat layout. The ones
marked *(Chrome)* are skipped: no async, no `std::thread`, `chromium::import!` and
gtest each assume Chrome's runtime and build system, and sandbx has neither.
[#328](https://github.com/danczw/sandbx/issues/328) tracks the migration, and its
phase sub-issues hold the status — not this file.

## `core` stays large to keep a constructor out of reach

The guide allows a larger crate for trait coherence or "a large foundational
library". `sandbx-core` arguably is the latter, and that is *not* the reason it stays
whole.

The reason is `VettedPath::from_wire` and the constructors beside it. Policy,
vetting, `fs_guard` and the helper live in one crate so those stay `pub(crate)`.
Split along the obvious seams and each becomes `pub`, and the type system stops being
what guards the vetting: a caller could mint a `VettedPath` for a path nothing
checked. `decision-policy.md` is why that guarantee is load-bearing.

Read the allowance and you will conclude the crate may be split as soon as someone
finds a tidier boundary. Read this and you will not — the boundary *is* the
visibility, and there is no tidier one.

## `use super::*` in a test module that moved to a file

The guide permits `use super::*` only in an *inline* module. Every test module here
is a sibling file instead — `#[cfg(test)] #[path = "foo_tests.rs"] mod tests;` — so
on a literal reading each one owes an explicit import list.

A test module in a file is the inline module with the braces replaced by a path
attribute; nothing about what it may reach changed. Naming every private item it
touches is churn that grows with the file and tells a reader nothing the `#[path]`
line did not. The exception is what the flat layout costs, and it is cheaper than the
alternative — keeping tests inline in order to stay literal.

## `catch_unwind` in the TUI: a deviation, not yet an exception

`crates/sandbx-tui/src/screen.rs:241` calls `catch_unwind`. The guide allows it as
defense in depth at an entry point and never as something a property relies on, and
this call is neither. It sits inside `Screen::drop`, and it stops a panic from
`Terminal::drop` — an `eprintln!` to a stderr that has hung up — from aborting while
the process is already unwinding, which loses the turn's earned exit code and the
audit trail it still held (#264).

So the mechanism *is* relied on, which is the part the guide refuses. This note does
not settle it. Phase 6 (#335) either removes the need or records it here as an
exception stating the condition that would retire it. Until then it is a known
deviation with an issue against it, not a silence.

## What the grace rule costs

Existing code is exempt from a rule until the phase that fixes it has landed; new and
changed code follows the guide. Both halves are load-bearing — without the first,
every phase blocks on every other; without the second, the tree drifts further out
while the migration runs.

**A reviewer cannot read conformance off the file in front of them.** Whether a
violation is a finding depends on which phase has landed and whether the line is new.
The diff answers the second question and only the tracking issue answers the first,
so every review pays this until Phase 7 closes.

**A file can hold both styles at once** — a module half-swept — and read as nobody's
intent. That is the price of not doing the whole tree in one unreviewable commit.

## Library rules in `core`, application rules elsewhere

`sandbx-core` follows the guide's library rules and every other crate its application
rules. The split is about who the caller is: `core`'s callers are the other six
crates and cannot be changed in lockstep with it, while a change inside
`sandbx-tui` has one caller and it is in this repo.

What this does *not* buy is `#[non_exhaustive]`. The guide scopes it to enums other
teams consume; there are no other teams, and `policy/sandbox.rs` depends on its
matches being exhaustive. Adding an axis has to break every match over axes — that compile error is
the check that a new axis cannot arrive without a row. `#[non_exhaustive]` would turn
it into a silently-taken wildcard arm, which is the defect `decision-policy.md`
records as *A new axis without a row fails the test*. It is refused in `core` too,
library rules notwithstanding.

## What this leaves open

Two of the departures above are consequences of choices taken before any code moved —
the one larger crate, and tests in sibling files. If either is revisited the departure
goes with it, so neither is evidence that the guide was wrong about anything.

The weakness, stated rather than designed around: nothing checks this file against the
tree. A fourth departure can be introduced and reviewed as ordinary code, because no
lint knows what the guide says, and all that stands between a deviation and an
unrecorded one is a reviewer who has read both. The dependency check and the
public-API diff narrow that for the two cases where it would cost most — a crate
reaching across a boundary, and a visibility widening. Nothing narrows the rest.
