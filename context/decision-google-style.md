# Decision: the Google Rust style guide, and where this repo departs from it

The workspace follows the [Google Rust style guide](https://google.github.io/styleguide/rustguide.html),
including the rules it marks *(Chromium)*, and none of those it marks *(Chrome)*. The
migration is tracked in #328, one sub-issue per phase; this file is what holds once the
migration is done, and what to answer a re-proposal with.

Until the phase that fixes a rule has landed, existing code is exempt from that rule.
New and changed code follows the guide from the start — so a review flags a deviation
in the lines a branch touches, and not in the code around them.

## What was decided

| Question | Decision |
|---|---|
| Crate size | One abstraction per crate. Not one file per crate: the guide says "ideally, but not necessarily", and a subsystem spread over several files (the turn loop, the session store) needs one crate whose `//!` can describe it whole |
| `sandbx-core` | Stays one larger crate around policy, vetting, `FsGuard` and the helper. See exception A |
| Which crate may depend on which | Checked in CI, because Cargo has no equivalent of the visibility lists that make small crates safe in Chromium |
| Unit tests | In the crate, in a sibling file: `#[cfg(test)] #[path = "foo_tests.rs"] mod tests;` |
| `sandbx-helper` | Its own binary crate, its end-to-end tests beside it |
| API rules | Library rules for `sandbx-core`, application rules everywhere else |
| `#[non_exhaustive]` | Not used. The guide scopes it to enums used by other teams; `NetworkPolicy` relies on a fourth state being a compile error at every site that would otherwise leave it unenforced |
| Panics | Only for bugs and broken invariants; `Result` for anything recoverable; `expect` over `unwrap` |
| Assertions | A message on every assert, saying why it holds or what the values were — never the condition again in words |
| rustfmt | The guide's options, on a pinned nightly used for formatting only. The build and the suite stay on stable |
| Test framework | `#[test]` and `#[tokio::test]` are this codebase's framework |
| Docs | A crate's `//!` says how it works and, when a reason guards it, why. `context/` keeps what spans crates |

## Exceptions

**A. `sandbx-core` is large to keep its constructors crate-private.** The guide allows a
larger crate for trait coherence or "a large foundational library". `sandbx-core` may be the
second, but that is not the reason. A crate boundary is the only boundary Rust's privacy
enforces: split policy from vetting and `VettedPath::from_wire` has to become `pub`, after
which any crate in the workspace can build a vetted path without vetting it. Inside one crate
it stays `pub(crate)` and the compiler is what refuses.

**B. `use super::*` in a test module loaded with `#[path]`.** The guide allows `use super::*`
only in inline modules. A sibling test file is the inline `mod tests` moved to its own file,
and naming every private item a suite reaches is churn with nothing for a reader to gain.

**C. `catch_unwind` in `Screen::drop`** (`crates/sandbx-tui/src/screen.rs`). Not settled:
a known deviation until #335 decides it. The guide allows `catch_unwind` only as defence in
depth at an entry point, never relied on. This one is relied on: `Terminal::drop`
`eprintln!`s when it cannot show the cursor, which panics on a dead stderr, and a panic inside
a `Drop` that is already unwinding aborts — losing the exit code and the audit trail (#264).

## House rules on top of the guide

**A test name is at most 50 characters.** `cargo test` prints the
name without the `///`, so what a test asserts has to be legible from the failure line alone.
Shorten by dropping what the file and module already say, never by abbreviating, and keep
the clause that distinguishes a test from its nearest sibling. A rename can break prose:
`context/` cites test names as the evidence for a claim, and nothing checks those
citations, so grep `context/` and `SECURITY.md` for the old name before the rename is done.

**A unit test never widens an API.** A unit test stays compiled into its crate so it can
reach private items. `crates/*/tests/` is a separate crate and sees only the public surface,
so a unit test cannot move there without making `pub` what was private for a reason.

| Test | Home |
|---|---|
| touches a private or `pub(crate)` item | the module's sibling `foo_tests.rs` |
| drives the crate's public API | `crates/<crate>/tests/<topic>.rs` |
| needs a sandbox-capable kernel | behind the `sandbox-integration` feature |

What a test has to assert to prove anything is in `guide-sandboxing.md`: most mechanisms
here fail closed, and a test expecting a denial passes through every one of those failures.

**Some doc comments are output, not commentary.** clap renders a doc comment on a CLI type
into `--help` — even with `about` set, unless `long_about = None` — and schemars turns one
on a tool's input struct into the JSON-schema `description` the model reads. A trim there
changes what a user or the model sees; diff the rendering, not the comment.

## Rejected, and likely to be proposed again

- **The *(Chrome)* rules.** "No `async`" exists because Rust futures cannot join Chrome's C++
  task scheduler, and "no new threads, use sequences" names that scheduler. Outside Chrome the
  two cannot both hold: `reqwest::blocking` runs a tokio runtime on a thread of its own, and
  racing a streamed turn against the interrupt key needs either `select!` or a thread. The
  three threads `src/` starts each block in the kernel, which is what a thread is for.
- **One file per crate.** It gives every file its own privacy boundary, at the cost of a
  `Cargo.toml` and an error type for a 30-line tool, and of any one home for a subsystem's
  description.
- **Splitting `sandbx-core` like every other crate.** See exception A.
