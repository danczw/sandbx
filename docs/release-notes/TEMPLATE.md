<!--
Copy to docs/release-notes/v<version>.md and commit it with the change. The
release gates on that file: no notes, no release.

One or two short paragraphs on the major changes and any upgrade hazard. The PR
list is appended at publish time, so no headings, no bullets, and nothing
restated from it. Budget: 12 lines, this comment excluded.

Check it before tagging:
  .github/scripts/check-release-notes.sh docs/release-notes/v<version>.md

context/guide-release-notes.md says what earns a place in the prose.
-->

**One sentence on what this release is.** Then what changed that a user would
notice, and what breaks if they upgrade without reading it.
