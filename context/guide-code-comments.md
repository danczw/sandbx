# Code comments

Keep the knowledge next to the code. Keep it short.

The tree had grown essays: multi-paragraph rationale on public items, rejected
alternatives, issue archaeology, restatements of what the item is named. The
problem is length, not location. A fact that explains an enforcement decision
belongs three lines above that decision, where the next person to edit it cannot
miss it — compressed to the clause that is load-bearing, not expanded into prose.

So: cut words, keep facts. A pass that deletes a kernel quirk, an ordering
requirement, or a "this does not imply that" has failed, however much shorter it
made the file.

## Budget

| Thing | Budget |
|---|---|
| public item (`///`) | one line; `missing_docs = "warn"` makes it mandatory |
| + a constraint a plausible edit would break | one more sentence, two if the mechanism needs naming |
| public enum variant or public field | one clause, and only because `missing_docs` fires on these too |
| private field, getter, `From`, `Default` | nothing, unless the name is genuinely ambiguous — then one clause |
| test function | nothing; the name and the `assert!` messages carry it |
| inline `//` | one or two lines, where the *why* is not derivable from the line |
| module `//!` | five lines: what the module owns, and the one thing a reader must know before editing it |

Anything over budget is a rewrite, not a deletion: find the sentence doing the
work and keep that one.

## Cut

- **Restatement.** `/// Read a file.` on `BuiltinTool::Read`. Variant and field
  names are the documentation; a `///` that paraphrases them is noise.
- **History.** "which produced #49", "was first proposed as", "used to be",
  "added in the commit that split the helper". `git log` and the issue tracker
  hold this and stay accurate. An issue number is allowed only when it points at
  open work.
- **Rejected alternatives**, unless the rejection is a trap someone will
  re-propose next month. Then one sentence: what fails, not the full argument.
- **Rhetoric and emphasis.** `**The table.**`, "deliberately", "irreducible
  residue", "which is worse than a flat failure would be". A doc comment is a
  reference entry.
- **Narration.** A `//` that says what the next line does.
- **Prose already in `context/*.md` or `SECURITY.md`** — but leave the one-line
  claim in the code and point: `` // Landlock has no path-scoped unix socket
  right before ABI V9; see `context/guide-sandboxing.md`. ``
- **Planned work.** File an issue (see `CLAUDE.md`).

## Keep

- Why a sequence cannot be reordered.
- Why a syscall, flag, or apparent redundancy is required.
- Where a magic constant or ABI number comes from.
- An asymmetry the type system does not enforce (`ReadExecute` confers read;
  nothing confers execute).
- A workaround and the condition that would let it go.

Two kinds of doc comment are not commentary at all and are out of scope: the ones
clap renders into `--help` (`sandbx-cli/src/lib.rs`) and the ones schemars turns
into a tool's JSON-schema `description` (`sandbx-tools/src/tools/*.rs`). Those
are user- and model-facing text. Leave them, and exclude them when reading a
crate's density.

`sandbx-core/src/helper/` is almost entirely this category. Expect it to shrink
by rewording rather than by deleting, and prefer one terse sentence to none on
any enforcement path.

## Before and after

```rust
/// Grant unix-domain sockets.
///
/// **All of them**, not a chosen one. The denial is a seccomp rule on
/// `socket(AF_UNIX, …)`, and seccomp compares register values: the path
/// passed to `connect` lives behind a pointer it cannot follow. Landlock
/// gained a path-scoped right for this in ABI V9 (Linux 7.1), and a
/// per-socket grant can be added once that is available in practice.
///
/// So this opens every pathname socket the filesystem policy can reach —
/// an ssh-agent, a docker socket, the session bus. Grant it deliberately,
/// and keep the filesystem policy narrow, because that is what still bounds
/// which sockets exist to be dialled.
```

```rust
/// Grant every unix-domain socket the filesystem policy can reach.
///
/// All or nothing: the denial is a seccomp rule on `socket(AF_UNIX, …)`, and
/// seccomp cannot follow the pointer to `connect`'s path. Per-socket grants
/// need Landlock ABI V9 (Linux 7.1). The filesystem policy is what bounds
/// which sockets exist to be dialled.
```

Four facts in, four facts out, a third of the lines.

## Verifying a pass

Comment lines (`///`, `//!`, `//`) as a share of all lines, before this guide:
core 36%, cli 32%, agent 29%, providers 26%, tools 22%. Under 15% is the smell
test everywhere except `sandbx-core/src/helper/`. It is a smell test, not a
quota.

A comment-only change leaves the code byte-identical. Check with
`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and
`cargo doc --no-deps` — trimming a referenced item breaks intra-doc links.
