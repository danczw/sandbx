# Bounding tool work

A timeout bounds a process. Six of the seven built-ins never start one, so a
timeout bounds nothing about them — they need a bound on *work* instead.

## The defect this fixed

`turn.rs` used to state a worst case:

```
max_rounds * (stream_timeout + calls * tool_timeout)
```

Every term but the first was wrong. `stream_timeout` bounds the stream, not a
tool call; `timeout` (`ExecutionContext`, 90 s) bounds `bash` and nothing
else. A `grep` over a huge tree had no clock on it at all and no budget either,
so one broad search could run until it finished — however long that was.

The formula is gone. **A turn has no total wall-clock bound to state.**

## Two kinds of bound

| | Input bound | Output bound |
|---|---|---|
| Caps | how much the tool *looks at* | how much it *hands back* |
| Hit means | stopped early, answer incomplete | answer complete, display trimmed |
| Marker | `"... stopped early: scan limit reached, results are incomplete"` | `"... truncated: showing 200 of 4000 results"` |

Conflating them is how a search that silently gave up looks identical to one that
found 4,000 matches and showed 200.

The knobs themselves — each one's phase, default, and which tool it bounds — are
the current shape, in [guide-tools.md](guide-tools.md#what-bounds-a-tool-call).

`max_bytes_scanned` is a total, not a per-file cap: a hundred 2 MiB files cost
the same as one 200 MiB file, and only a total sees that.

> **`MAX_FILE_BYTES` is what makes the 64 MiB figure finite.** The budget is
> *checked before* each read, not clamped — so a single file can overshoot it.
> What keeps the overshoot bounded is the separate per-file skip: files above
> 2 MiB are skipped unread. Worst case is therefore 64 + 2 MiB, and a caller using
> `with_max_bytes_scanned` cannot move the 2 MiB half.

> **`read` and `edit` have no input cap.** `read_file` calls `read_to_string`
> uncapped; `max_bytes` trims what is *returned*, after the whole file has been
> allocated. A 10 GiB file in a readable root is one allocation, and `edit` then
> holds the original plus the replacement. `grep` guards exactly this case with
> `MAX_FILE_BYTES`; these two do not.

## Bound the work, not the answer

`walk_readable` takes a `max_files` cap and returns:

```rust
pub struct ReadableWalk {
    pub files: Vec<PathBuf>,
    pub truncated: bool,      // ← did we stop early, or is that the whole tree?
}
```

A bare `Vec` cannot answer that question, and the caller has to know: 10,000
files returned means one thing if the tree has 10,000 files and another if it has
a million.

The check sits at **both** push sites in the walk (symlinked file and regular
file), with exactly-the-cap meaning *not* truncated:

```rust
if files.len() == max_files {
    truncated = true;
    break 'walk;
}
```

`cap = 4, tree = 4` → `truncated == false`. `cap = 4, tree = 20` → `true`. Pinned
by `walk_of_exactly_the_cap_is_not_truncated`.

## Related

- `ToolLimits` was `OutputLimits` until it grew the two input bounds; the rename
  is what the type now actually covers.
