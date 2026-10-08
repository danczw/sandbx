# Onboarding

A read-through that takes a new engineer from "what is this" to being able to
open `helper/mod.rs` and say why the order of `apply` is load-bearing. One
sitting per chapter, general to specific.

Security is the centre of gravity throughout. sandbx is a sandbox; a chapter
that skipped the boundary would be describing a different project.

## Who this is for

Someone comfortable with Rust's core ideas — ownership, traits, enums, `Result`
— but not with its corners, and who knows the theory of namespaces and syscall
filtering without having written against the kernel. Where a chapter needs an
edge case of the language or the origin of an ABI number, it explains it inline
rather than assuming it.

This is an on-ramp, not an authority. [`context/`](../) holds a guide or a
decision record for every subsystem, and [`SECURITY.md`](../../SECURITY.md) is
the normative account of what the sandbox enforces — both written for a reader
who already has the vocabulary. These chapters supply the vocabulary and then
point at them. Where a chapter and `SECURITY.md` disagree about what the code
does, `SECURITY.md` is right.

## The order

| chapter | covers |
|---|---|
| [01 — what sandbx is](01-what-sandbx-is.md) | the product and its thesis, the five subcommands, what the kernel has to provide, and the five commands to run first |
| [04 — the architecture](04-the-architecture.md) | three views of one system — the processes, the request path, the boundaries. The spine every later chapter locates itself in |
| [05 — seven crates](05-seven-crates.md) | the static view under 04: the dependency graph, who owns what, and the three mechanisms that keep one crate the only one able to spawn a process |
| [16 — how the repo is maintained](16-how-the-repo-is-maintained.md) | guide versus decision, the Rust tests that hold the prose to the code, and a walkthrough of your first PR |

Chapters are numbered by position in that order, so a gap is a chapter that is
not in this directory yet; the whole list is on the tracking issue. An index
that linked a file nobody had written would be the one navigation surface
pointing at a hole, which is the thing this numbering is arranged to avoid.

**If you need to be useful tomorrow:** 01, then 04, then
[`SECURITY.md`](../../SECURITY.md) itself.

## Links into the code

The rest of `context/` deliberately never links to a source file. Commit
`bafc713` stripped the last `file:line` citations after one of them had drifted
onto the wrong item, and house style since then is a backticked crate-relative
path plus the identifier named in prose.

These chapters take a narrow exemption, because an on-ramp read on a phone has
to be able to open the file it is talking about. The convention it keeps is the
reason the house rule exists: **the link addresses the file, and the prose
addresses the identifier.** A refactor that moves a function two hundred lines
down breaks neither. No line numbers, and no commit permalinks.

Two kinds of figure are deliberately absent for the same reason. A chapter never
quotes a comment-length, module-size or name-length budget — it links
[guide-code-comments.md](../guide-code-comments.md),
[guide-module-layout.md](../guide-module-layout.md) and
[guide-naming.md](../guide-naming.md) and describes what they constrain. And a
chapter never restates the Landlock ABI floor or the kernel version it needs:
`every_prose_copy_of_the_floor_is_current` pins that figure in seven named
files, and its own comment says that each further copy is another way for a trim
to break the build. Both figures live in one place and are read there.

## Critique is marked

A chapter is allowed to say that a design looks questionable. Being told only
why every choice was right teaches a codebase as scripture, and an onboarding
read is the best chance anyone gets to see the thing fresh. Three conditions
keep that from degrading into noise:

- **It never sits inside a description of behaviour.** An objection gets its own
  bullet, led by **Worth questioning:**, so it cannot be mistaken for
  documentation of what the code does.
- **It engages the decision record that already considered it,** where one
  exists. Several of the `decision-*.md` files are records of something priced
  and declined. An objection that does not know about the record is noise; one
  that has read it and still disagrees, for a reason the record did not weigh,
  is what the project wants.
- **A mechanism that does not match a claim is a finding, not a critique.**
  [`CLAUDE.md`](../../CLAUDE.md) is explicit that where the mechanism and the
  claim disagree, one of them changes — the claim is weakened, or the mechanism
  is widened to match. That goes to the maintainer, not into a chapter.

The last chapter collects the objections that look substantial, and ends with
the path from one to a filed issue.

## Ticking it off

Progress lives on the tracking issue, not in this directory. A checkbox in a
repo file would mean a commit per chapter read, and the issue's checklist is
tickable from the GitHub mobile app, which is where this is likely to be read.

## What a chapter looks like

- **It opens by naming which part of the system it is about,** and links back to
  [04](04-the-architecture.md), so a reader who arrived from a search knows
  where they are standing.
- **It closes with a short "you should now be able to explain" list.** Prose,
  not checkboxes. A bullet there that reads as unfamiliar marks a section worth
  a second pass.
- **Snippets are copied verbatim and kept short.** They are there to be read in
  place; the link above one is how you see the rest of the file.
- **An issue is cited as a bare number,** usually parenthesised, and never with
  a status attached. Whether #230 is open is a question for GitHub, and a doc
  that answered it would start being wrong the day it was merged.
