#!/bin/sh
# Implements the support policy in SECURITY.md. A script so the self-test can gate
# the decision at merge time — a mis-marked release cannot be un-pushed.

set -eu

# Nine digits at most, because these fields reach `[ -gt ]`: a wider number is
# not orderable by any POSIX shell, and a shell that cannot order it reports a
# parse error rather than a comparison.
num='(0|[1-9][0-9]{0,8})'

# Only an exact 1.0-or-later version may become "latest"; anything else,
# recognised or not, is a pre-release. Build metadata is matched explicitly, since
# a hyphen inside it is not a pre-release suffix.
channel() {
  if printf '%s' "${1#v}" \
    | grep -qE "^[1-9][0-9]{0,8}\.$num\.$num(\+[0-9A-Za-z.-]+)?\$"; then
    echo release
  else
    echo prerelease
  fi
}

# Whether a tag carries a version this script can place in order at all. Every
# unrecognised shape classifies `prerelease`, so without this a published tag
# `latest` cannot parse would be skipped as harmless and read as "nothing higher
# is published".
known() {
  printf '%s' "${1#v}" \
    | grep -qE "^$num\.$num\.$num(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?\$"
}

# Build metadata is excluded from semver precedence, so it comes off before any
# comparison.
core() {
  c="${1#v}"
  echo "${c%%+*}"
}

# Hand-rolled because `sort -V` is GNU-only and this is /bin/sh. Both arguments
# have passed `channel`, so every field is digits only, has no leading zero and is
# at most nine wide — which is what makes a field-wise `[ -gt ]` safe here.
higher_of() {
  a="${1#*.}"; a_min="${a%%.*}"
  b="${2#*.}"; b_min="${b%%.*}"
  if [ "${1%%.*}" -gt "${2%%.*}" ]; then echo "$1"; return 0; fi
  if [ "${2%%.*}" -gt "${1%%.*}" ]; then echo "$2"; return 0; fi
  if [ "$a_min" -gt "$b_min" ]; then echo "$1"; return 0; fi
  if [ "$b_min" -gt "$a_min" ]; then echo "$2"; return 0; fi
  if [ "${1##*.}" -gt "${2##*.}" ]; then echo "$1"; return 0; fi
  echo "$2"
}

# Whether $1 may take GitHub's "latest" link, against the already-published tags
# on stdin. Takes the set as input rather than querying it: everything in
# .github/scripts/ has to run without a workflow, so the API call stays in
# release.yml and the self-test below can feed this a table.
latest() {
  if [ "$(channel "$1")" != release ]; then echo false; return 0; fi
  mine="$(core "$1")"
  verdict=true
  # The second test is for an unterminated final line, which `read` assigns before
  # reporting EOF: `gh api --jq` terminates its last record, a hand-fed `printf`
  # need not.
  while read -r other || [ -n "$other" ]; do
    [ -n "$other" ] || continue
    if ! known "$other"; then
      echo "::error::published tag $other carries no orderable version" >&2
      return 1
    fi
    [ "$(channel "$other")" = release ] || continue
    # An equal version answers itself, so it never demotes: ties keep the link.
    if [ "$(higher_of "$mine" "$(core "$other")")" != "$mine" ]; then
      verdict=false
    fi
  done
  echo "$verdict"
}

self_test() {
  status=0
  while read -r tag want; do
    got="$(channel "$tag")"
    if [ "$got" != "$want" ]; then
      echo "::error::$tag classified $got, want $want"
      status=1
    fi
  done <<'TAGS'
v1.0.0 release
v1.2.3 release
v10.0.0 release
v1.0.10 release
v1.0.0+exp-sha.5114f85 release
v0.1.0-alpha.6 prerelease
v0.2.0 prerelease
v0.2.0-rc.1 prerelease
v1.0.0-rc.1 prerelease
v1 prerelease
v1x prerelease
v1.2 prerelease
v1.0.0.1 prerelease
v1.01.0 prerelease
v1.0.9999999999 prerelease
v0 prerelease
nightly prerelease
TAGS
  # `v1.0.0+exp.1` beating `v1.0.0-rc.1` is not a typo: `channel` gates on the raw
  # tag, where `+` is release and `-` is not.
  while read -r tag existing want; do
    case "$existing" in -) existing='' ;; esac
    got="$(printf '%s' "$existing" | tr ',' '\n' | latest "$tag" 2>/dev/null)" \
      || got=error
    if [ "$got" != "$want" ]; then
      echo "::error::$tag against $existing judged $got, want $want"
      status=1
    fi
  done <<'ROWS'
v1.0.0 - true
v1.0.0 v0.1.0-alpha.6,v0.9.0 true
v1.5.0 v2.0.0-rc.1 true
v2.0.1 v2.0.0,v1.5.1 true
v1.6.0 v1.5.3 true
v1.10.0 v1.9.0 true
v2.0.0 v2.0.0 true
v1.0.0+exp.1 v1.0.0-rc.1 true
v1.0.1 v1.0.0+exp-sha.5114f85 true
v1.0.1+exp-sha.5114f85 v1.0.0 true
v1.0.0+exp-sha.5114f85 v1.0.1 false
v1.5.1 v2.0.0,v1.5.0 false
v1.5.1 v1.5.3 false
v1.9.0 v1.10.0 false
v0.2.0 v0.1.0 false
v0.1.0-alpha.13 v0.1.0-alpha.12 false
nightly - false
v2.0.1 v2.0 error
v1.0.1 v1.0.9999999999 error
ROWS
  # Once through argv with a redirect, the way release.yml calls it. The table
  # above pipes into the function, so a `verdict` confined to a subshell passes
  # there and fails only in production.
  got="$("$0" --latest v1.5.1 <<'ONE'
v2.0.0
ONE
)"
  if [ "$got" != false ]; then
    echo "::error::--latest through argv judged $got, want false"
    status=1
  fi
  return "$status"
}

case "${1-}" in
  --self-test) self_test ;;
  --latest) latest "${2:?usage: release-channel.sh --latest <tag> < published}" ;;
  "" | -*)
    echo "usage: release-channel.sh <tag> | --latest <tag> | --self-test" >&2
    exit 2
    ;;
  *) channel "$1" ;;
esac
