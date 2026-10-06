#!/bin/sh
# Implements the support policy in SECURITY.md. A script so the self-test can gate
# the decision at merge time — a mis-marked release cannot be un-pushed.

set -eu

# Only an exact 1.0-or-later version may become "latest"; anything else,
# recognised or not, is a pre-release. Build metadata is matched explicitly, since
# a hyphen inside it is not a pre-release suffix.
channel() {
  num='(0|[1-9][0-9]*)'
  if printf '%s' "${1#v}" \
    | grep -qE "^[1-9][0-9]*\.$num\.$num(\+[0-9A-Za-z.-]+)?\$"; then
    echo release
  else
    echo prerelease
  fi
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
v0 prerelease
nightly prerelease
TAGS
  return "$status"
}

case "${1-}" in
  --self-test) self_test ;;
  "" | -*) echo "usage: release-channel.sh <tag> | --self-test" >&2; exit 2 ;;
  *) channel "$1" ;;
esac
