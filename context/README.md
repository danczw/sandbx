# context/

What spans crates. A fact about one crate lives in that crate's rustdoc, so start
with `cargo doc --open`: each crate's `//!` says what it owns and what it refuses,
and that is the vocabulary the docs here assume. Which crate may depend on which
is `deny.toml`, checked against the graph by `.github/scripts/deny-wrappers.py`.

`guide-` describes a subsystem as it currently is; `decision-` records why a
choice was made, and stays useful after the code moves.

## Reading order

1. `SECURITY.md` — what is claimed
2. `guide-sandboxing.md` — how it is enforced
3. `decision-policy.md` — where policy becomes kernel state, why there is one
   table, the one bound that is not path-keyed, why a grant is pinned to the
   object the harness vetted, and what happens when a grant covers a path sandbx
   owns
4. `decision-port-allowlist.md` — why a TCP port list costs UDP, what bounding
   egress to a host rather than a port would cost, and why a name allowlist is a
   hosts file and not a responder
5. `decision-helper-audit-channel.md` — how a decision made inside the helper
   gets out, and why a grant names a path and one flag names bytes instead
6. `decision-provider-seam.md` — why there is no provider trait, and where the
   vendor's vocabulary stops
7. `decision-approval-gate.md` — what sits between the model and a tool, and
   how much it claims
8. `decision-credentials.md` — where a key comes from, why a sandboxed tool is
   handed none, and the one name that is refused
9. `decision-on-disk-state.md` — what sandbx writes outside the working
   directory, and who may read it
10. `decision-thinking-replay.md` — why a reasoning block is replayed inside a
    turn and nowhere else
11. `guide-testing.md` — what a test has to assert, where it lives, and how long
    its name may be
12. `guide-ci.md` — what runs before a push, and what runs after
13. `guide-release-notes.md` — which half of a release body is written by hand,
    and which GitHub generates
14. `decision-google-style.md` — which style guide the code follows, and where
    it departs from it

## One home per fact

A fact lives in one place, and a second mention is a pointer to it. A comment
that has grown into an essay means the essay belongs here or in the crate's
`//!`, and the code needs a one-line pointer. Nothing measures a doc's length, so
the bound is placement, not size.
