# Decision: the Google Rust style guide, and where sandbx departs from it

Why the workspace follows [Google's Rust style
guide](https://google.github.io/styleguide/rustguide.html) rather than a house style
of its own, which of its rules are skipped, and the departures that are deliberate.
The guide is the mechanism; this is what the choices were between, and what guards
each departure against being re-proposed as an oversight.

The guide carries one tag, `[chrome]`, on five rules. Two are adopted here on their
merits: small crates, and the flat file layout for a crate's sources. Three are
skipped — no async, no `std::thread`, and the import mechanism — as is the Chrome
bullet of "use the right per-codebase test framework". Those four assume Chrome's
runtime or build system and sandbx has neither; the two adopted ones assume nothing
beyond Cargo.

Read the tag alone and you will conclude all five are out of scope, and that phases
3 and 4 of the migration are building on rules the repo skips. They are not: the tag
records which codebase asked for a rule, not whether it travels.
[#328](https://github.com/danczw/sandbx/issues/328) tracks the migration, and its
phase sub-issues hold the status — not this file.

## The flat layout, and how a file is named under it

Every crate's `src/` is flat (#333). A leaf module with a primary item is named
after it, module and file both, as the guide asks: `SandboxError` is
`error::sandbox_error`, in `sandbox_error.rs`. A leaf with no one item it is
about may be named as desired, and here its file takes its module path joined
with `_`, so `helper_ruleset_rights.rs` is `helper::ruleset::rights`. A
`#[path]` on every nested `mod` line keeps the module tree, a flat directory
having no other way to hold one; a crate root's code modules carry none, and its
test sibling does, being named after the crate (`guide-testing.md`).

So a file's name does not always spell its module path: `helper_refusal.rs` is
`error::helper_refusal`, not `helper::refusal`; `sandbx-cli`'s `agent_error.rs`
is `error::agent_error`, not a child of `agent`; and `requested.rs` is
`helper::ruleset::requested`, not a crate-root module. The `#[path]` naming the
file is where its parent is found. A primary-item name can also take the
spelling a later join would produce, so a new joined name is checked against
the files already there.

The tree is deep enough to need this only because `core` stays whole (below):
the guide expects a crate small enough that its modules sit at the top. Naming
every file after its last segment instead (`rights.rs`) is the reading that does
not fit — `core` alone would hold two `resolver.rs`, `helper::resolver` and the
crate's own (#449).

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

## Library rules in `core`, application rules elsewhere

`sandbx-core` follows the guide's library rules and every other crate its application
rules. The split is about who the caller is: `core`'s callers are the eight
crates that depend on it and cannot be changed in lockstep with it, while a
change inside `sandbx-tui-input` has one caller and it is in this repo.

What this does *not* buy is `#[non_exhaustive]`. The guide scopes it to enums other
teams consume; there are no other teams, and `sandbox_policy.rs` depends on its
matches being exhaustive. Adding an axis has to break every match over axes: that
compile error is the check that a new axis cannot arrive without a row.
`#[non_exhaustive]` would turn it into a silently-taken wildcard arm, which is the
defect `decision-policy.md` records as *A new axis without a row fails the test*.
It is refused in `core` too, library rules notwithstanding.

## What this leaves open

The one departure above is a consequence of a choice taken before any code moved:
the larger crate. If that is revisited the departure goes with it, so it is not
evidence that the guide was wrong about anything. The sibling-file test layout is
not a departure: it costs the guide's import rules nothing, and is a local
preference on #328's decision 4.

The weakness, stated rather than designed around: nothing checks this file against the
tree. Another departure can be introduced and reviewed as ordinary code, because no
lint knows what the guide says, and all that stands between a deviation and an
unrecorded one is a reviewer who has read both. The dependency check and the
public-API diff narrow that for the two cases where it would cost most — a crate
reaching across a boundary, and a visibility widening. Nothing narrows the rest.
