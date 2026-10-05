#!/bin/sh
# Check one release-notes file against context/guide-release-notes.md.
#
#     .github/scripts/check-release-notes.sh docs/release-notes/v0.1.0-alpha.7.md
#
# A script, not an inline `run:` block, so it runs without pushing a tag — the
# gate it feeds fails only once the tag is public.

set -eu

file="${1:?usage: check-release-notes.sh <file>}"
paragraphs=2
lines=12

[ -f "$file" ] || { echo "::error::$file does not exist"; exit 1; }

# Blanked in place, not deleted with the line: deleting merges the paragraphs
# around a standalone comment, and drops prose sharing a line with an inline one.
body="$(awk '
  {
    line = $0; out = ""
    while (length(line)) {
      if (open) {
        p = index(line, "-->")
        if (p == 0) { line = ""; break }
        line = substr(line, p + 3); open = 0
      } else {
        p = index(line, "<!--")
        if (p == 0) { out = out line; line = ""; break }
        out = out substr(line, 1, p - 1); line = substr(line, p + 4); open = 1
      }
    }
    print out
  }
' "$file")"

fail() { echo "::error::$file $1"; exit 1; }

printf '%s' "$body" | grep -q '[^[:space:]]' \
  || fail "has no prose outside its comments"

# A copy pushed unedited would publish the template's placeholder as the summary.
printf '%s\n' "$body" | grep -qF 'One sentence on what this release is' \
  && fail "still carries TEMPLATE.md's placeholder"

# The PR list is appended at publish time and supplies the structure. ATX needs
# a space after the hashes, so a leading issue ref like `#142` is prose.
printf '%s\n' "$body" \
  | grep -qE '^[[:space:]]*(#+([[:space:]]|$)|([*+-]|[0-9]+[.)])[[:space:]])' \
  && fail "has a heading or a bullet; keep it to prose"

printf '%s\n' "$body" | grep -qE '^[[:space:]]*(={2,}|-{2,})[[:space:]]*$' \
  && fail "has a setext heading; keep it to prose"

# Physical lines, blanks included, leading and trailing ones trimmed: counting
# only non-blank lines lets blank padding pass a file of any length.
trimmed="$(printf '%s\n' "$body" | awk '
  { buf[NR] = $0; if (NF) { if (!first) first = NR; last = NR } }
  END { for (i = first; i <= last; i++) print buf[i] }
')"
n="$(printf '%s\n' "$trimmed" | wc -l)"
p="$(printf '%s\n' "$trimmed" | awk 'NF && !seen { n++; seen = 1 } !NF { seen = 0 } END { print n + 0 }')"

echo "$file: lines=$n paragraphs=$p"
[ "$p" -le "$paragraphs" ] || fail "is $p paragraphs, budget is $paragraphs"
[ "$n" -le "$lines" ] || fail "is $n lines, budget is $lines"
