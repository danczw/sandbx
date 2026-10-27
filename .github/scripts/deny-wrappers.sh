#!/bin/sh
# Checks `deny.toml`'s workspace dependency allowlist against the real graph (#329).
#
# `cargo deny check bans` cannot do this. It reads a block's `name` as a package to look
# for, so a name matching nothing is vacuous rather than wrong: the block bans a package
# that does not exist, the crate the typo meant becomes unbanned, and every edge into it
# goes unchecked. That prints `bans ok` and exits 0 — a green gate over a boundary nobody
# looked at. Measured on #415 and reproduced against a second block.
#
# Two weaker holes close with it, both named in `deny.toml`'s own comments: a crate
# nothing lists at all ("omission reads as permission"), and an array naming a parent
# with no edge, which `cargo deny` reports as `warning[unused-wrapper]` and passes. All
# three are invisible to `cargo deny` and visible from `cargo metadata`.
#
# Runs in the `audit` job before `cargo-deny-action`, for the reason the release-channel
# check goes first: a new advisory fails that action and would mask this.
#
# `--self-test` runs the checks against scratch workspaces instead of this repo, one per
# case, and asserts both the exit code and which error fired.

set -eu

# Only `sandbx-*` blocks are checked. A third-party ban is a legitimate entry for a
# package deliberately absent from the graph, and asserting it resolves would fail on
# exactly the bans that are doing their job.
prefix=sandbx-

command -v jq >/dev/null 2>&1 || {
    echo "::error::jq missing: it is how the dependency graph is read"
    exit 1
}

# `--no-deps` needs no registry and no lockfile resolution, so the runner image's cargo
# is enough and no toolchain step precedes this in CI (`guide-ci.md`). Guarded anyway
# for the message: without it the failure is a bare non-zero from a command
# substitution, which reads as a broken script rather than a missing tool.
command -v cargo >/dev/null 2>&1 || {
    echo "::error::cargo missing: it is how the dependency graph is read"
    exit 1
}

# `deny.toml`'s blocks, as `NAME <name>` and `PAIR <name> <parent>` lines. awk rather
# than a TOML parser because `/bin/sh` has none: the shape is `[[bans.deny]]`, then
# `name`, then `wrappers` as either one line or a multi-line array, with comments
# anywhere between. A block whose `name` never arrives reports `BAD` and is an error
# below, never a skip — #393's lesson, where turning an unaddressable crate into a skip
# is what made that gate go quiet.
parse_deny() {
    awk '
        /^\[\[bans\.deny\]\]/ {
            if (started && name == "") bad++
            started = 1; name = ""; inarr = 0; next
        }
        !started { next }
        /^name = / { gsub(/^name = "|"$/, ""); name = $0; print "NAME " name; next }
        /^wrappers = \[.*\]/ {
            if (name == "") { bad++; next }
            n = split($0, parts, /"/)
            for (i = 2; i <= n; i += 2) print "PAIR " name " " parts[i]
            next
        }
        /^wrappers = \[/ { if (name == "") { bad++; next } inarr = 1; next }
        inarr && /^\]/ { inarr = 0; next }
        inarr {
            n = split($0, parts, /"/)
            for (i = 2; i <= n; i += 2) print "PAIR " name " " parts[i]
            next
        }
        END { if (started && name == "") bad++; if (bad) print "BAD " bad }
    ' "$1"
}

# Checks the workspace rooted at the current directory. Echoes `::error::` lines and
# returns 1 on any failure, so the self-test can read both the status and the text.
check_workspace() {
    # Two statements and not one pipeline, for the reason `guide-ci.md` gives for the
    # `msrv` job: `/bin/sh` has no `pipefail`, so a failed `cargo metadata` would take
    # jq's exit status and leave every list below empty — which reads as "nothing to
    # check" and passes.
    metadata=$(cargo metadata --format-version 1 --no-deps)

    packages=$(printf '%s' "$metadata" | jq -r '.packages[].name' | sort -u)

    # The real graph as `<child> <parent>` pairs, workspace crates only. Dev and build
    # edges count: `wrappers` reads the whole graph, so a dev-dependency is a parent too.
    edges=$(printf '%s' "$metadata" | jq -r '
        [.packages[].name] as $ws
        | .packages[]
        | .name as $parent
        | .dependencies[]
        | select(.name as $n | $ws | index($n))
        | "\(.name) \($parent)"' | sort -u)

    blocks=$(parse_deny deny.toml)

    if printf '%s\n' "$blocks" | grep -q '^BAD '; then
        echo "::error::deny.toml has a [[bans.deny]] block with no parseable name."
        echo "::error::This script addresses blocks by name, so an unnamed block is unchecked."
        return 1
    fi

    names=$(printf '%s\n' "$blocks" | sed -n 's/^NAME //p' | sort -u)
    declared=$(printf '%s\n' "$blocks" | sed -n 's/^PAIR //p' | sort -u)
    status=0

    # 1. Every `sandbx-*` block names a real package. The hole this script exists for.
    for name in $names; do
        case "$name" in "$prefix"*) ;; *) continue ;; esac
        printf '%s\n' "$packages" | grep -qx "$name" || {
            echo "::error::deny.toml bans '$name', which is not a workspace package."
            echo "::error::A block naming nothing is vacuous: '$name' is unbanned and its"
            echo "::error::edges unchecked, while 'cargo deny check bans' still exits 0."
            status=1
        }
    done

    # 2. Every crate something depends on has a block. Omission reads as permission,
    #    which is why the crates nothing depends on are the only legitimate absences.
    for crate in $(printf '%s\n' "$edges" | cut -d' ' -f1 | sort -u); do
        printf '%s\n' "$names" | grep -qx "$crate" || {
            parents=$(printf '%s\n' "$edges" | awk -v c="$crate" '$1 == c { printf "%s ", $2 }')
            echo "::error::'$crate' is depended on by ${parents}but has no deny.toml block."
            echo "::error::Nothing then constrains who may depend on it."
            status=1
        }
    done

    # 3. Each array is exactly the real parent set. A missing parent is `error[banned]`,
    #    which cargo-deny catches; an extra one is only `warning[unused-wrapper]`, which
    #    it does not, and which overstates who may depend on the crate.
    for crate in $names; do
        case "$crate" in "$prefix"*) ;; *) continue ;; esac
        printf '%s\n' "$packages" | grep -qx "$crate" || continue
        want=$(printf '%s\n' "$edges" | awk -v c="$crate" '$1 == c { print $2 }' | sort -u)
        got=$(printf '%s\n' "$declared" | awk -v c="$crate" '$1 == c { print $2 }' | sort -u)
        [ "$want" = "$got" ] && continue
        echo "::error::'$crate' lists the wrong parents in deny.toml."
        echo "::error::  graph:     $(printf '%s ' $want)"
        echo "::error::  deny.toml: $(printf '%s ' $got)"
        status=1
    done

    return "$status"
}

# A scratch workspace: `b` and `c` both depend on `a`, `c`'s edge being a dev one so the
# dev-edge arm is covered. `$1` is the `[[bans.deny]]` body under test.
fixture() {
    dir=$1
    mkdir -p "$dir/a/src" "$dir/b/src" "$dir/c/src"
    cat > "$dir/Cargo.toml" <<'EOF'
[workspace]
resolver = "3"
members = ["a", "b", "c"]
EOF
    for crate in a b c; do
        cat > "$dir/$crate/Cargo.toml" <<EOF
[package]
name = "sandbx-$crate"
version = "0.0.0"
edition = "2024"
publish = false
EOF
        : > "$dir/$crate/src/lib.rs"
    done
    cat >> "$dir/b/Cargo.toml" <<'EOF'

[dependencies]
sandbx-a = { path = "../a" }
EOF
    cat >> "$dir/c/Cargo.toml" <<'EOF'

[dev-dependencies]
sandbx-a = { path = "../a" }
EOF
}

# Each row is a case: name, expected exit code, a string the output must contain, and the
# `deny.toml` body. A fresh directory per row — leaked state between rows is how a
# scratch harness reports a verdict about the wrong fixture.
self_test() {
    status=0
    root=$(mktemp -d)
    # shellcheck disable=SC2064
    trap "rm -rf '$root'" EXIT

    run_case() {
        case_name=$1
        want_rc=$2
        want_text=$3
        body=$4

        dir="$root/$case_name"
        fixture "$dir"
        printf '%s\n' "$body" > "$dir/deny.toml"

        out=$(cd "$dir" && check_workspace 2>&1) && got_rc=0 || got_rc=1

        if [ "$got_rc" != "$want_rc" ]; then
            echo "::error::self-test '$case_name': exit $got_rc, want $want_rc"
            printf '%s\n' "$out" | sed 's/^/  /'
            status=1
            return
        fi
        if [ -n "$want_text" ] && ! printf '%s\n' "$out" | grep -qF "$want_text"; then
            echo "::error::self-test '$case_name': output lacks '$want_text'"
            printf '%s\n' "$out" | sed 's/^/  /'
            status=1
            return
        fi
        echo "  ok  $case_name"
    }

    # The correct file. Nothing depends on b or c, so their absence is right.
    run_case clean 0 '' '[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-b", "sandbx-c"]'

    # The hole. `cargo deny check bans` exits 0 on this file.
    run_case typo 1 "is not a workspace package" '[[bans.deny]]
name = "sandbx-a-nope"
wrappers = ["sandbx-b", "sandbx-c"]
[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-b", "sandbx-c"]'

    run_case missing_block 1 "has no deny.toml block" '[[bans.deny]]
name = "sandbx-b"
wrappers = ["sandbx-c"]'

    run_case extra_parent 1 "lists the wrong parents" '[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-b", "sandbx-c", "sandbx-nobody"]'

    # Drops the *normal* parent, keeping the dev one.
    run_case missing_normal_parent 1 "lists the wrong parents" '[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-c"]'

    # Drops the *dev* parent, keeping the normal one. A separate case from the above and
    # not a reworded copy of it: a graph read that skipped dev edges would pass this one
    # while still failing that one, and dev is the arm `sandbx-core`'s own entry needs.
    run_case missing_dev_parent 1 "lists the wrong parents" '[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-b"]'

    # Carries a correct block alongside the unnamed one, so checks 2 and 3 both pass and
    # only the unnamed-block guard can fail this. Without the correct block, an empty
    # name set makes check 2 fire on its own and the guard could be deleted unnoticed.
    run_case unnamed_block 1 "no parseable name" '[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-b", "sandbx-c"]
[[bans.deny]]
wrappers = ["sandbx-b"]'

    # A multi-line array is the shape `sandbx-core`'s entry uses.
    run_case multiline_array 0 '' '[[bans.deny]]
name = "sandbx-a"
# A comment between the name and the array, as every real block has.
wrappers = [
    "sandbx-b",
    "sandbx-c",
]'

    # A third-party ban names a package deliberately not in the graph. Checking it would
    # fail the bans that work, so it is skipped by prefix rather than resolved.
    run_case third_party_ban_ignored 0 '' '[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-b", "sandbx-c"]
[[bans.deny]]
name = "openssl"'

    [ "$status" -eq 0 ] || return 1
    echo "self-test: all cases pass"
}

if [ "${1:-}" = "--self-test" ]; then
    self_test
    exit "$?"
fi

cd "$(dirname "$0")/../.."
check_workspace || exit 1
echo "deny.toml: $(parse_deny deny.toml | grep -c '^NAME ') blocks match the graph"
