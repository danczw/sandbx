#!/usr/bin/env python3
"""Checks `deny.toml`'s workspace dependency allowlist against the real graph (#329).

`cargo deny check bans` cannot do this. It reads a `[[bans.deny]]` block's `name` as a
package to look for, so a name matching nothing is vacuous rather than wrong: the block
bans a package that does not exist, the crate the typo meant becomes unbanned, and every
edge into it goes unchecked. `cargo deny` says `warning[unused-wrapper]` for each listed
parent and then `bans ok`, exit 0 — non-fatal, so a green gate over the boundary #329
exists to hold. Measured on #415 against `sandbx-turn` and reproduced against
`sandbx-approval`, so it is the tool's behaviour and not a suspicion about it.

Two weaker holes close with it, both non-fatal to `cargo deny` the same way: a crate
something depends on having no block at all ("omission reads as permission", which
`deny.toml`'s own header calls unexpressed), and a `wrappers` array naming a parent with
no edge, which is `warning[unused-wrapper]` and passes while overstating who may depend
on the crate.

Python rather than `/bin/sh` like its three neighbours, for one reason: this has to read
TOML, and `/bin/sh` has no parser for it. An awk approximation was written first and a
review found five ways to break it — a comment inside a multi-line array injecting a
phantom parent, a trailing comment after `name`, a `name` key in any later table being
absorbed, an indented closing bracket swallowing the next table, and key order inside a
block being significant when TOML says it is not. `tomllib` has been in the standard
library since 3.11 and removes that whole class rather than patching it; the runner this
job uses already has Python, since the zizmor step is `pipx`.

`--self-test` runs the checks against scratch workspaces instead of this repo, one
fixture per case, and asserts both the exit status and which error fired.
"""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import tomllib

# Check 1's only input, and only because the name alone cannot settle its question: a
# block naming no package is either a typo in a workspace crate or a deliberate
# third-party ban, and nothing in the file distinguishes them. Every member is
# `sandbx-*`, so a `sandbx-*` name resolving to nothing is read as the typo.
#
# The cost, since it is real: a third-party crate actually named `sandbx-*` — a
# typosquat, the package this repo would most want to ban — needs check 1 relaxed first.
# Checks 2 and 3 key on graph membership instead, so an off-prefix member is still
# fully checked.
PREFIX = "sandbx-"


def read_graph(root: pathlib.Path) -> tuple[set[str], dict[str, set[str]]]:
    """The workspace's package names, and `child -> {parents}` over internal edges.

    `--no-deps` needs no registry and no lockfile resolution, so the runner image's
    cargo is enough and no toolchain step precedes this in CI (`guide-ci.md`). Dev and
    build edges count: `wrappers` reads the whole graph, so a dev-dependency is a parent
    too — which `sandbx-core`'s own entry relies on.
    """
    done = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        capture_output=True,
        text=True,
        cwd=root,
    )
    if done.returncode != 0:
        # Relayed rather than swallowed by `check=True`: a malformed manifest, or a
        # runner cargo too old for the edition, is cargo's message and not this one's.
        raise RuntimeError(
            f"cargo metadata failed (exit {done.returncode}):\n{done.stderr.strip()}"
        )
    meta = json.loads(done.stdout)
    packages = {p["name"] for p in meta["packages"]}
    if not packages:
        raise RuntimeError("cargo metadata reported no workspace packages")

    edges: dict[str, set[str]] = {}
    for package in meta["packages"]:
        for dep in package.get("dependencies", []):
            if dep["name"] in packages:
                edges.setdefault(dep["name"], set()).add(package["name"])
    return packages, edges


def read_deny(path: pathlib.Path) -> dict:
    """`deny.toml` as tomllib gives it, so key order and comments cannot matter."""
    with path.open("rb") as handle:
        return tomllib.load(handle)


# `[graph]` keys that remove workspace edges from the graph cargo-deny walks, which makes
# its own `wrappers` enforcement vacuous for those edges while it still exits 0 —
# measured on 0.20.2, where `exclude-dev = true` turns a real dev parent into
# `warning[unused-wrapper]`. Refused so cargo-deny stays a check behind this one rather
# than being replaced by it; `sandbx-core`'s entry rests entirely on a dev edge.
GRAPH_KEYS_THAT_HIDE_EDGES = ("exclude", "exclude-dev")


def check(root: pathlib.Path, out) -> int:
    """Checks the workspace at `root`. Writes `::error::` lines to `out`.

    Returns the number of blocks naming a workspace member that were compared, or -1
    on any failure, so the summary reports what was actually compared rather than how
    many blocks exist.
    """
    packages, edges = read_graph(root)
    deny = read_deny(root / "deny.toml")
    blocks = deny.get("bans", {}).get("deny", [])
    failed = False

    def error(*lines: str) -> None:
        nonlocal failed
        failed = True
        for line in lines:
            print(f"::error::{line}", file=out)

    for key in GRAPH_KEYS_THAT_HIDE_EDGES:
        if key in deny.get("graph", {}):
            error(
                f"deny.toml's [graph] sets {key!r}.",
                "That removes workspace edges from the graph cargo-deny walks, so its"
                " own wrappers enforcement goes vacuous while it exits 0.",
            )

    named = []
    for index, block in enumerate(blocks):
        # `crate` is cargo-deny's synonym for `name`, accepted and undeprecated on
        # 0.20.2, so a file written that way is correct and reading only `name` would
        # fail CI over a spelling. It is a PackageSpec rather than a bare name, hence
        # the `@` split below.
        name = block.get("name") or block.get("crate")
        if not isinstance(name, str) or not name:
            error(
                f"deny.toml's [[bans.deny]] block #{index + 1} has no name.",
                "This check addresses blocks by name, so an unnamed block is unchecked.",
            )
            continue
        named.append((name, block))

    # A version requirement narrows a block to the versions it matches, so one no crate
    # satisfies is vacuous in exactly the way a typo'd name is: cargo-deny matches
    # nothing and reports `bans ok` at exit 0. Measured on 0.20.2 as both `version =
    # "=9.9.9"` and `crate = "sandbx-a@9.9.9"`, which are the same hole in two spellings.
    #
    # Rejected even when the pin currently matches: every workspace crate shares one
    # inherited version, so a pin that resolves today goes vacuous at the next release
    # and nothing would say so.
    for name, block in named:
        pinned = "@" in name
        bare = name.split("@", 1)[0]
        if bare not in packages:
            continue
        if pinned or "version" in block:
            requirement = name if pinned else repr(block["version"])
            error(
                f"'{bare}''s deny.toml block pins a version ({requirement}).",
                "A version no crate satisfies makes the block vacuous while cargo-deny"
                " still exits 0, and every pin here goes vacuous at the next release.",
            )

    # The pin is reported above; everything downstream keys on the bare name, so a pinned
    # block is still checked for its parents rather than skipped on a second fault.
    named = [(name.split("@", 1)[0], block) for name, block in named]

    # 1. Every `sandbx-*` block names a real package. The hole this script exists for.
    for name, _ in named:
        if name.startswith(PREFIX) and name not in packages:
            error(
                f"deny.toml bans '{name}', which is not a workspace package.",
                f"A block naming nothing is vacuous: '{name}' is unbanned and its edges",
                "unchecked, while 'cargo deny check bans' still exits 0.",
            )

    # 2. Every crate something depends on has a block. Omission reads as permission,
    #    which is why the crates nothing depends on are the only legitimate absences.
    declared_names = {name for name, _ in named}
    for crate in sorted(edges):
        if crate not in declared_names:
            parents = " ".join(sorted(edges[crate]))
            error(
                f"'{crate}' is depended on by {parents} but has no deny.toml block.",
                "Nothing then constrains who may depend on it.",
            )

    # 3. Each array is exactly the real parent set, and present. A missing parent is
    #    `error[banned]`, which cargo-deny catches; an extra one is only
    #    `warning[unused-wrapper]`, which it does not, and which overstates who may
    #    depend on the crate. An absent array bans the crate outright — cargo-deny does
    #    reject that, but with a message about the crate rather than about this file.
    #    Keyed on membership of the graph alone, *not* on the prefix: check 2 is
    #    satisfied by a block merely existing, so this is the only check that reads an
    #    off-prefix member's array at all.
    compared = 0
    for name, block in named:
        if name not in packages:
            continue
        compared += 1
        wrappers = block.get("wrappers")
        want = edges.get(name, set())
        if wrappers is None or wrappers == []:
            error(
                f"'{name}' has a deny.toml block with no wrappers, which bans it",
                f"outright rather than permitting nothing. Its real parents are:"
                f" {' '.join(sorted(want)) or '(none, so the block should be absent)'}",
            )
            continue
        # Validated before `set()`: a non-string entry is unhashable or unsortable, and
        # a bare string is a set of its characters, so both would report nonsense or
        # raise a traceback where a named error belongs.
        if not isinstance(wrappers, list) or not all(
            isinstance(w, str) for w in wrappers
        ):
            error(
                f"'{name}' has a wrappers value that is not a list of strings:"
                f" {wrappers!r}.",
                "Each entry names a crate that may depend on this one.",
            )
            continue
        got = set(wrappers)
        if got != want:
            error(
                f"'{name}' lists the wrong parents in deny.toml.",
                f"  graph:     {' '.join(sorted(want)) or '(none)'}",
                f"  deny.toml: {' '.join(sorted(got)) or '(none)'}",
            )

    # A comparison of nothing is not a pass — `guide-ci.md`'s *A glob that matches
    # nothing must fail*, which asks it of any check that iterates.
    #
    # No `deny.toml` can reach this, and it is kept anyway: check 2 requires a block per
    # crate with dependents and those names are packages by construction, so `compared`
    # cannot be zero while check 2 passes. It asserts against a future edit to check 3's
    # keying, which is why no fixture covers it — one of two such guards here, with the
    # empty-package-set check in `read_graph`.
    #
    # Gated on `edges`: a workspace with no internal dependency needs no blocks, and
    # that is a correct empty result rather than a broken check.
    if not failed and edges and compared == 0:
        error(
            "no deny.toml block was compared against the graph, though "
            f"{len(edges)} crate(s) have dependents.",
            f"{len(blocks)} block(s) were read and {len(packages)} package(s) found, so"
            " this is a bug in the check rather than a correct empty result.",
        )

    return -1 if failed else compared


FIXTURE_CRATES = ("a", "b", "c")


def write_fixture(root: pathlib.Path, deny: str) -> None:
    """`b` depends on `a`; `c` dev-depends on `a`, so the dev-edge arm is covered."""
    root.mkdir(parents=True)
    (root / "Cargo.toml").write_text(
        '[workspace]\nresolver = "3"\nmembers = ["a", "b", "c"]\n'
    )
    for crate in FIXTURE_CRATES:
        (root / crate / "src").mkdir(parents=True)
        (root / crate / "src" / "lib.rs").write_text("")
        (root / crate / "Cargo.toml").write_text(
            f'[package]\nname = "sandbx-{crate}"\nversion = "0.0.0"\n'
            'edition = "2024"\npublish = false\n'
        )
    with (root / "b" / "Cargo.toml").open("a") as handle:
        handle.write('\n[dependencies]\nsandbx-a = { path = "../a" }\n')
    with (root / "c" / "Cargo.toml").open("a") as handle:
        handle.write('\n[dev-dependencies]\nsandbx-a = { path = "../a" }\n')
    (root / "deny.toml").write_text(deny)


# name, expected ok/fail, a string the output must contain, the deny.toml body.
# A fresh directory per case: leaked state between cases is how a scratch harness
# reports a verdict about the wrong fixture.
CASES: list[tuple[str, bool, str, str]] = [
    # Nothing depends on b or c, so their absence is correct.
    ("clean", True, "", """
[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-b", "sandbx-c"]
"""),
    # The hole. `cargo deny check bans` exits 0 on this file.
    ("typo", False, "is not a workspace package", """
[[bans.deny]]
name = "sandbx-a-nope"
wrappers = ["sandbx-b", "sandbx-c"]
[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-b", "sandbx-c"]
"""),
    # `sandbx-a` is depended on and has no block, and only check 2 can fail this: the
    # third-party ban is skipped by prefix, so checks 1 and 3 have nothing to say. A
    # fixture that tripped check 3 too would exit 1 on that message with check 2's
    # membership test unexercised.
    ("missing_block_only", False, "has no deny.toml block", """
[[bans.deny]]
name = "openssl"
"""),
    ("extra_parent", False, "lists the wrong parents", """
[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-b", "sandbx-c", "sandbx-nobody"]
"""),
    # Drops the normal parent, keeping the dev one.
    ("missing_normal_parent", False, "lists the wrong parents", """
[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-c"]
"""),
    # Drops the dev parent, keeping the normal one. Independent of the case above and
    # not a reworded copy: a graph read that skipped dev edges would pass this one while
    # still failing that one, and dev is the arm `sandbx-core`'s entry needs.
    ("missing_dev_parent", False, "lists the wrong parents", """
[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-b"]
"""),
    # Carries a correct block alongside the unnamed one, so checks 2 and 3 both pass and
    # only the unnamed-block guard can fail this.
    ("unnamed_block", False, "has no name", """
[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-b", "sandbx-c"]
[[bans.deny]]
wrappers = ["sandbx-b"]
"""),
    # An array with no parents bans the crate outright. cargo-deny rejects it too, but
    # naming the crate rather than this file, so the summary must not say "match".
    ("empty_wrappers", False, "bans it", """
[[bans.deny]]
name = "sandbx-a"
wrappers = []
"""),
    ("absent_wrappers", False, "no wrappers", """
[[bans.deny]]
name = "sandbx-a"
"""),
    # A third-party ban names a package deliberately absent from the graph, and carries
    # no wrappers. Both are legitimate, so check 1's prefix test must spare it.
    ("third_party_ban_spared", True, "", """
[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-b", "sandbx-c"]
[[bans.deny]]
name = "openssl"
"""),
    # A `wrappers` value that is not a list of strings. Before the isinstance test these
    # raised a traceback (unsortable mixed set, unhashable list) or silently became a set
    # of characters, reporting `deny.toml: - a b d n s x` as the declared parents.
    ("wrappers_not_a_list", False, "not a list of strings", """
[[bans.deny]]
name = "sandbx-a"
wrappers = "sandbx-b"
"""),
    ("wrappers_entry_not_a_string", False, "not a list of strings", """
[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-b", 7]
"""),
    ("wrappers_entry_is_a_list", False, "not a list of strings", """
[[bans.deny]]
name = "sandbx-a"
wrappers = [["sandbx-b"], "sandbx-c"]
"""),
    # A version requirement no crate satisfies is a typo'd name in another spelling:
    # cargo-deny matches nothing and still exits 0.
    ("version_requirement", False, "pins a version", """
[[bans.deny]]
name = "sandbx-a"
version = "=9.9.9"
wrappers = ["sandbx-b", "sandbx-c"]
"""),
    # cargo-deny's synonym for `name`, accepted and undeprecated. Correct for it, so it
    # must be read rather than rejected over a spelling.
    ("crate_key_plain", True, "", """
[[bans.deny]]
crate = "sandbx-a"
wrappers = ["sandbx-b", "sandbx-c"]
"""),
    # The same vacuity as `version =`, reached through the PackageSpec. Rejected even
    # though this pin matches today, because the workspace version bumps every release.
    ("crate_key_pinned", False, "pins a version", """
[[bans.deny]]
crate = "sandbx-a@0.0.0"
wrappers = ["sandbx-b", "sandbx-c"]
"""),
    # A pinned block is still checked for its parents, so this reports both faults
    # rather than stopping at the pin.
    ("crate_key_pinned_and_wrong_parents", False, "lists the wrong parents", """
[[bans.deny]]
crate = "sandbx-a@9.9.9"
wrappers = ["sandbx-b"]
"""),
    # `[graph]` keys that hide workspace edges from cargo-deny. Refused so it stays a
    # check behind this one; the arrays themselves are correct in both.
    ("graph_exclude_dev", False, "[graph] sets 'exclude-dev'", """
[graph]
exclude-dev = true

[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-b", "sandbx-c"]
"""),
    ("graph_exclude", False, "[graph] sets 'exclude'", """
[graph]
exclude = ["sandbx-c"]

[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-b", "sandbx-c"]
"""),
    # The five shapes the awk parser got wrong, kept as cases so a future rewrite back
    # into shell cannot reintroduce them quietly.
    ("multiline_array", True, "", """
[[bans.deny]]
name = "sandbx-a"
# A comment between the name and the array, as every real block has.
wrappers = [
    "sandbx-b",
    "sandbx-c",
]
"""),
    ("comment_inside_array", True, "", """
[[bans.deny]]
name = "sandbx-a"
wrappers = [
    # The "b" edge is direct, and this comment has quotes in it.
    "sandbx-b",
    "sandbx-c",
]
"""),
    ("trailing_comment_after_name", True, "", """
[[bans.deny]]
name = "sandbx-a" # why this crate is constrained
wrappers = ["sandbx-b", "sandbx-c"]
"""),
    ("name_key_in_a_later_table", True, "", """
[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-b", "sandbx-c"]

[[bans.skip]]
name = "sandbx-b"
"""),
    ("indented_closing_bracket", True, "", """
[[bans.deny]]
name = "sandbx-a"
wrappers = [
    "sandbx-b",
    "sandbx-c",
  ]

[sources]
unknown-registry = "deny"
"""),
    ("wrappers_before_name", True, "", """
[[bans.deny]]
wrappers = ["sandbx-b", "sandbx-c"]
name = "sandbx-a"
"""),
]


def write_off_prefix_fixture(root: pathlib.Path, deny: str) -> None:
    """A workspace whose members are not all `sandbx-*`.

    Its own case, rather than a fifth column on every row above, because it is the only
    one that needs a different member list. `sbx-helper` is depended on by `sandbx-b`,
    so checks 2 and 3 both have something to say about it — and before check 3 keyed on
    graph membership rather than the prefix, it had an array nothing ever compared.
    """
    root.mkdir(parents=True)
    (root / "Cargo.toml").write_text(
        '[workspace]\nresolver = "3"\nmembers = ["a", "b", "helper"]\n'
    )
    for directory, package in (("a", "sandbx-a"), ("b", "sandbx-b"),
                               ("helper", "sbx-helper")):
        (root / directory / "src").mkdir(parents=True)
        (root / directory / "src" / "lib.rs").write_text("")
        (root / directory / "Cargo.toml").write_text(
            f'[package]\nname = "{package}"\nversion = "0.0.0"\n'
            'edition = "2024"\npublish = false\n'
        )
    with (root / "b" / "Cargo.toml").open("a") as handle:
        handle.write(
            '\n[dependencies]\nsandbx-a = { path = "../a" }\n'
            'sbx-helper = { path = "../helper" }\n'
        )
    (root / "deny.toml").write_text(deny)


OFF_PREFIX_CASES: list[tuple[str, bool, str, str]] = [
    ("off_prefix_member_correct", True, "", """
[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-b"]
[[bans.deny]]
name = "sbx-helper"
wrappers = ["sandbx-b"]
"""),
    # The hole finding 1 named: an off-prefix member's array omits its real parent and
    # names one that does not exist. Check 2 is satisfied by the block existing, so only
    # check 3 can catch it — and it could not while it skipped on the prefix.
    ("off_prefix_member_wrong_array", False, "lists the wrong parents", """
[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-b"]
[[bans.deny]]
name = "sbx-helper"
wrappers = ["sandbx-nobody-at-all"]
"""),
]


def self_test() -> int:
    root = pathlib.Path(tempfile.mkdtemp())
    failures = 0
    total = 0
    try:
        for build, cases in ((write_fixture, CASES),
                             (write_off_prefix_fixture, OFF_PREFIX_CASES)):
            for name, want_ok, want_text, body in cases:
                total += 1
                directory = root / name
                build(directory, body.lstrip("\n"))
                buffer = io.StringIO()
                try:
                    compared = check(directory, buffer)
                except Exception as exc:  # a crash is a failure, not a verdict
                    print(f"::error::self-test '{name}': raised {exc!r}")
                    failures += 1
                    continue
                output = buffer.getvalue()
                got_ok = compared >= 0

                if got_ok != want_ok:
                    print(f"::error::self-test '{name}': "
                          f"{'passed' if got_ok else 'failed'}, want "
                          f"{'pass' if want_ok else 'fail'}")
                    print("\n".join("  " + line for line in output.splitlines()))
                    failures += 1
                    continue
                if want_text and want_text not in output:
                    print(f"::error::self-test '{name}': output lacks {want_text!r}")
                    print("\n".join("  " + line for line in output.splitlines()))
                    failures += 1
                    continue
                print(f"  ok  {name}")
    finally:
        shutil.rmtree(root, ignore_errors=True)

    # The argv guard, covered here rather than left to the comment above it: it is the
    # one check outside `check()`, and an argv that fell through to the real check would
    # pass the CI step with the self-test never having run.
    #
    # Its own `::error::` lines are swallowed, not shown: GitHub renders that prefix as
    # an annotation on the job whatever the exit status, so a passing self-test would
    # otherwise decorate a green run with four errors it had deliberately provoked.
    for argv in (["--selftest"], ["--help"], ["deny.toml"], ["--self-test", "extra"]):
        total += 1
        sink = io.StringIO()
        with contextlib.redirect_stderr(sink):
            got = main(argv)
        if got != 2:
            print(f"::error::self-test 'argv {argv}': exited {got}, want 2")
            failures += 1
        else:
            print(f"  ok  argv {' '.join(argv)}")

    if failures:
        return 1
    # Asserted, not just printed: a loop that silently iterated zero cases would
    # otherwise report success, which is the defect this whole script is about.
    expected = len(CASES) + len(OFF_PREFIX_CASES) + 4
    if total != expected:
        print(f"::error::self-test ran {total} cases, expected {expected}")
        return 1
    print(f"self-test: {total} cases pass")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    if argv:
        # Not a fall-through to the real check: a mistyped flag would then pass the step
        # while the self-test that guards this checker never ran.
        print(f"::error::unknown argument: {' '.join(argv)}", file=sys.stderr)
        print("::error::usage: deny-wrappers.py [--self-test]", file=sys.stderr)
        return 2

    root = pathlib.Path(__file__).resolve().parents[2]
    compared = check(root, sys.stdout)
    if compared < 0:
        return 1
    print(f"deny.toml: {compared} workspace-crate blocks match the graph")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
