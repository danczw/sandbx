# Release notes

Extracted from `v0.1.0-alpha.3`, `.4` and `.5`, which already agree. This is the
shape they share, written down so the next one does not have to re-derive it.

The notes are a **claim about what changed**, in the same register as
`SECURITY.md`: what was wrong, what is true now, and what the reader must do.
Not a commit log — the commit log is generated and then thrown away.

## Section order

Order is load-bearing: the thing that breaks a reader goes first, before anything
that merely interests them.

| # | Section | When | Why there |
|---|---|---|---|
| 1 | Lead line, bold | always | One sentence naming the release's character: `**A correctness release.**`, `**The first release under the `sandbx` name.**` |
| 2 | Upgrade hazard | when one exists | `## Read this first: …` or `## Upgrade from any earlier alpha`. A reader who stops here must still not be surprised |
| 3 | Pre-alpha blockquote | always | `> Still pre-alpha…` — support scope, stated every time, never assumed known |
| 4 | The substance | always | One `##` per theme, prose with `(#N)` refs. The *why*, not the diff |
| 5 | `## Also in this release` | when there is a tail | Real but secondary work, still prose |
| 6 | `## Smaller things` | when the tail is long | Bullets, one line each, `(#N)` |
| 7 | `## Upgrading` | when anything moved | Split CLI surface from library callers — they break differently |
| 8 | `## Verifying this build` | always | Commands the reader runs, not a claim they trust |

Omit a section rather than write it empty. `alpha.4` states *"no upgrade
hazard"* in its lead line instead of carrying an empty section 2 — say it, then
drop the heading.

## Skeleton

```markdown
**<One sentence: the character of this release.>**

> Still pre-alpha. There is no agent yet, only the sandbox beneath it. Only the
> latest pre-release is supported; there are no backports.

## Read this first: <the hazard>          ← only if one exists

**<What breaks, in bold.>** <Why it breaks, what the old behaviour was, and the
one command that tells the reader whether it affects them.>

## <Theme>

<Prose. What was claimed, what was actually true, what is true now. Name the
mechanism and the issue: `Fixed in #76.` Behaviour changes get their own
paragraph starting "Behaviour change worth knowing:".>

## Also in this release

**<Short title>** (#N). <Two or three sentences.>

## Upgrading

**<What changes at the command line.>** <Usually: nothing.>

<What changes for library callers, which is often where a tightening lands.>

## Verifying this build

```
sha256sum -c sandbx-<tag>-<target>.tar.gz.sha256
file sandbx            # static-pie linked, no glibc floor
sandbx --version       # <version>
```

<One closing paragraph: still pre-1.0, no backports, SECURITY.md is the current
statement of what is and is not claimed.>
```

## Rules the three releases already follow

- **Bold the claim, not the heading.** `**A write grant handed out read in the
  child**` then the explanation. A reader scanning bold text gets the release.
- **An issue number per substantive item**, in parentheses: `(#50)`, `Fixed in
  #76.` This is the one place issue archaeology belongs — unlike code comments,
  where `context/guide-code-comments.md` cuts it.
- **Quantify when it is load-bearing.** *"Measured on a 6.18 kernel whose
  effective Landlock ABI is V8: **every run was partly enforced.**"* A severity
  claim without a number is an opinion.
- **Name the consequence a reader would not predict.** `alpha.3` on PID
  namespaces: an unhandled `SIGTERM` is ignored, and `/proc/self/stat` disagrees
  with `getpid()`. Neither follows from "process lifetime is now enforced".
- **Say what did *not* change.** *"No change to the policy surface: the same
  flags grant the same access."* Absence of change is information.
- **Verification is commands, not assurances.** `alpha.4`'s *"## Verified"*
  records that the published archive was downloaded and exercised for both
  permits and denials — not that it was built green.

## Mechanics

`release.yml` publishes with `--generate-notes`, so the body starts as GitHub's
`## What's Changed` list of merged PRs. That list is scaffolding:

| Release | Generated list kept? |
|---|---|
| `alpha.3` | yes, appended below the prose |
| `alpha.4` | no |
| `alpha.5` | no |

The later two are the pattern. Write the real notes, then replace the body:

```sh
gh release edit <tag> --notes-file notes.md
```

Curate **after** verifying the artifact, not before — `alpha.4`'s notes claim the
archive was checked, and that claim has to be true when written.

## Two things that are not release notes

- **A migration guide.** If upgrading needs more than a section, the hazard is
  too large for an alpha's notes; say so and link an issue.
- **A roadmap.** What is planned goes on an issue, on a milestone. Same rule as
  everywhere else in this repo — see `CLAUDE.md`.
