# `decision=` records the access

The audit trail records what the agent *did*, not what the policy *decided*.
`allowed` means a handle was obtained; `absent` means the name denoted nothing;
`denied` means something refused.

The alternative was to record verdicts, which is what the guard natively
produces: it decides on resolution, so the decision is available before any
syscall is attempted. That reading was coherent and cheaper, and it is the one
the code had by accident. It was rejected (#182, #187).

## What the verdict reading cost

`FsGuard::permit` emitted `allowed` the moment a path resolved inside a granted
root. Between that and the `open` the leaf can be deleted, or swapped for a
symlink that `O_NOFOLLOW` then refuses. So the trail carried
`decision="allowed" tool="read" subject="…"` for a file nothing read a byte of.

Defensible as a record of the verdict — but then the trail cannot answer "what
did the agent see" at all, which is the question an operator brings to it. The
record was not wrong so much as answering a question nobody asked.

The verdict reading also forecloses `absent` permanently. If `decision=` records
verdicts, an absence is not one: no policy refused a path that was never there,
so there is nothing for the value to record. And `decision=` is a wire field —
adding a value is additive, removing one is not — so the foreclosure is the
expensive direction to get wrong.

## What the access reading costs

**Noise.** One record per failed `read`, where before there were none. An agent
walking a tree by guesswork now leaves a line per guess. Accepted, because that
is the same information read the other way: a prompt-injected model probing
filenames inside a grant it already holds discloses nothing the grant did not
give it, but the *pattern* of attempts is a signal, and under the verdict
reading it was invisible.

**A second place the path is written.** Accepted; `absent` and `denied` already
both write it.

**`ls` needed a new entry point.** `tracing` is `sandbx-core`'s dependency alone,
so an accurate record for `ls` could not live in `sandbx-tools` — hence
`FsGuard::read_dir`. It closes no check-to-use window that `check_read` left
open; `read_dir` has no handle form for `O_NOFOLLOW` to guard. What it closes is
the gap between the verdict and the trail.

The root confirmation #212 added is part of the verdict, and the reading survives it
unchanged: a root measured as replaced refuses before any open, so its `denied` is a
refusal record and not a verdict one, and a root that confirms still writes nothing
by confirming — `allowed` waits for the open as it did. The one thing to keep is that
the reason recorded and the error returned come off the same measurement. A second
stat for the record could disagree with the first and write a line contradicting what
the caller was told; `a_moved_root_records_the_reason_it_returns` pins the pair.

## Why the two issues were one

Moving `allowed` below the open only works if a refused open then gets a record
of its own, which is `absent`. Saying instead that `allowed` is the verdict
forecloses `absent`. Deciding them apart is how the trail ends up with `allowed`
meaning the verdict in one place and the access in another — which is why all six
filesystem tools moved together rather than only the two that hold handles.
