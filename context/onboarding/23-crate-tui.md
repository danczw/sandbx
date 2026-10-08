# The tui crate decides nothing, and sanitises everything it draws

[`sandbx-tui`](../../crates/sandbx-tui/) is the screen one turn is drawn on and
the keys that stop it: five source files, under a thousand lines, the smallest
crate in the workspace. In [04 — the architecture](04-the-architecture.md) it is
the box a turn is *reported* in, and the one crate with no row in View 3's table
of boundaries — no policy, no gate, no session, no client. 04 also sets the
frame: `tui` is not a sixth subcommand but `agent-run`'s flags derived into the
same policy, reported elsewhere.

What the screen draws, and what interrupting a turn loses, belongs to
[15 — the seven tools and the screen](15-tools-and-the-screen.md) and to
[guide-tui.md](../guide-tui.md), the authority. This chapter is the map
underneath: which file holds which type, what is `pub` and what deliberately is
not, where the tests are, and one security property that belongs to this crate's
*manifest*. The **driver** is [24](24-crate-cli.md)'s — `cli/src/agent/tui.rs`
enters the screen, starts the key reader, races the turn against a keypress and
overrides the gate's `settled`.

## The module tree

```
src/lib.rs          re-exports four names; no policy, no gate, no session here
   transcript.rs    AgentEvent folded into entries, and the control bytes a cell
                    may not hold — no terminal behind it, so it is unit-tested
   view.rs          the layout: the transcript tail-aligned over a status bar
   screen.rs        Screen — raw mode and the alternate screen, put back on drop
   input.rs         Keys — the reader thread, and the press a turn awaits
```

| module | what it holds | covered in |
|---|---|---|
| [`lib.rs`](../../crates/sandbx-tui/src/lib.rs) | four `mod` lines and four `pub use` lines — the whole public surface | here |
| [`transcript.rs`](../../crates/sandbx-tui/src/transcript.rs) | `Transcript`, `Entry`, `Kind`, `printable` — the fold, and the sanitiser | here, as the centre; [15](15-tools-and-the-screen.md) for why a renderer gets a security chapter |
| [`view.rs`](../../crates/sandbx-tui/src/view.rs) | `draw`, `Hint`, `GUTTER_MARK` — rows, styles, the status bar | here for the layout; [guide-tui.md](../guide-tui.md) owns the gutter argument |
| [`screen.rs`](../../crates/sandbx-tui/src/screen.rs) | `Screen` — raw mode, the alternate screen, the `Drop`, the latched failure | here |
| [`input.rs`](../../crates/sandbx-tui/src/input.rs) | `Keys`, `Seen`, `interrupts` — the reader thread and the two awaits | here; [15](15-tools-and-the-screen.md) for what the interrupt costs |

Tests are inline, in the file whose private items they touch, as
[guide-module-layout.md](../guide-module-layout.md) asks: `transcript.rs`,
`view.rs` and `input.rs` carry a `mod tests`, there is no
`crates/sandbx-tui/tests/` directory, and `screen.rs` has none — it is the one
file that needs a real terminal.

## lib.rs is four names, and the manifest is the interesting half

Four `mod` lines and four `pub use` lines, and no `pub mod`, so no module path
is part of the API: a caller gets four names and their methods —
`Transcript::new`/`event`/`call`/`note`,
`Screen::enter`/`draw`/`redraw`/`failure`, `Keys::listen`/`stop`/`press`,
`Hint::Running`/`Done`. Deliberately *not* exported is the shape of a
transcript: `Entry` and `Kind` are `pub(crate)`, as are `Transcript::entries`,
`rounds`, `tokens` and `view::draw`. The only way out of a `Transcript` is a
drawn frame, so no caller can read the folded entries back and print them where
the fold does not cover.

The dependency edge is the second half of
[`Cargo.toml`](../../crates/sandbx-tui/Cargo.toml).

```toml
ratatui = { version = "=0.30.2", default-features = false, features = [
  "crossterm",
  "unstable-rendered-line-info",
] }
sandbx-providers = { path = "../sandbx-providers" }
# `sync` alone: the key thread reaches the turn through a watch channel, and
# nothing here spawns a task or arms a timer.
tokio = { version = "1.53.1", default-features = false, features = ["sync"] }
```

One internal crate, and `serde_json` as a dev-dependency only. Read that as a
negative fact stated at the type level: **a renderer cannot leak what it cannot
name.** With no edge to `sandbx-core`, `sandbx-tools`, `sandbx-agent` or
`sandbx-session`, nothing here can mention a `SandboxPolicy`, an
`ExecutionContext`, a `BuiltinTool`, a `CallGate` or a session transcript — not
"does not" but cannot, as a build error. The borrowed vocabulary is two types:
`transcript.rs` names `sandbx_providers::AgentEvent`, and its tests name
`StopReason`.

- **Worth questioning:** how much of that the dependency graph carries. Four
  crates' vocabulary is ruled out by a missing edge; the rest is not.
  `sandbx-providers` also exports `AnthropicClient` and
  `anthropic_api_key`/`resolve_api_key`, so the renderer *can* name the client
  and the credential resolver, which makes
  [guide-repo-map.md](../guide-repo-map.md)'s "nothing here knows of a policy or
  a provider" exact about the first half and loose about the second —
  discipline, where for the policy and the gate it is the compiler.
  [decision-provider-seam.md](../decision-provider-seam.md) argues by its own
  method: it sealed the vendor boundary by leaving `Prompt` without a
  `Serialize`, so nothing above `anthropic.rs` *can* post a neutral type. The
  same move is open here — the two event types in a crate of their own — priced
  against an eighth crate in a workspace whose seven are a feature.

## transcript.rs is the fold, and the fold is a sanitiser

The file to read, and the only one in the crate with a decision in it.
`Transcript` holds the `Vec<Entry>` in arrival order, a `show_thinking` flag, a
`rounds` counter and `tokens`, a pair of `Option<u32>`. An `Entry` is a `Kind`
and a `String`, and `Kind`'s five variants — `Prompt`, `Answer`, `Reasoning`,
`Call`, `Note` — are the crate's only classification, the view styling and
guttering by them.

Two fields exist because of the API rather than the screen. `rounds` is counted
off `Stop` events, since "no event carries the turn's own bound" — the screen
can say how many rounds happened, not how many were allowed. `tokens` is two
`Option`s rather than a struct because the API omits either independently, a
reported zero being a figure where an absence must not take a shown one back off
the screen (`an_unreported_count_is_not_a_reported_zero`).

### The fold is exhaustive, so a new event has to be decided here

```rust
    /// Fold one event in. A reasoning block and a redacted one are dropped, both carrying
    /// replay material that must not render.
    pub fn event(&mut self, event: &AgentEvent) {
        match event {
            AgentEvent::Text { delta } => self.append(delta, Kind::Answer),
            AgentEvent::Thinking { delta } if self.show_thinking => {
                self.append(delta, Kind::Reasoning);
            }
            AgentEvent::Stop { .. } => self.rounds += 1,
```

`AgentEvent` has seven variants and the match names every one with no `_` arm,
so an eighth is a compile error here. Three arms drop, and each is a decision:

- **`ThinkingBlock` and `RedactedThinking` are never entries.** Both carry
  replay material whose rule is "never log, render or store it", and a renderer
  is exactly the thing that would. [02](02-what-a-harness-is.md) and
  [decision-thinking-replay.md](../decision-thinking-replay.md) own why; the pin
  is `no_replayable_reasoning_block_is_ever_an_entry`, which folds a `Text`
  event first and asserts that produced something, so a fold that dropped
  everything could not pass it.
- **`Thinking` is gated on the flag, not on the event's absence**, the API
  sending the delta regardless of what was asked for.
- **`ToolCallRequested` draws nothing**, a requested call still being refusable.
  Only a settled one gets a row, arriving through `Transcript::call` from the
  caller's gate; the test feeds a `bash` call carrying `rm -rf /`.

Deltas coalesce: `append` extends the last entry when the kind matches and opens
a new one otherwise, so a `Call` row splits the answer where it happened.

### The bytes a cell may not hold

The threat first, because it is not cosmetic. Model output is
attacker-influenced text: a prompt injection in a file the agent read comes back
through the model and into the pane, and ratatui writes a cell's content to the
terminal as it was given. A surviving escape sequence could reposition the
cursor, rewrite the rows above itself — the account of what a tool just did
included — or set the terminal's title. The module doc draws the conclusion:
"model-chosen text is stripped here, not at the caller, because the screen is
what an escape sequence inside it would rewrite". `printable` is the stripper:

```rust
fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());

    for c in text.chars() {
        match c {
            '\n' => out.push('\n'),
            '\t' => out.push_str("    "),
            c if c.is_control() || invisible(c) || forgeable(c) => out.push('\u{fffd}'),
            c => out.push(c),
        }
    }
```

Every string that becomes entry text goes through it: the opening prompt in
`new`, each delta in `append`, every `call` and `note` line in `push`. Four
classes: `\n` survives because the view splits rows on it, `\t` becomes spaces
because nothing renders a cell holding one, and `is_control` and the two
denylists below all become U+FFFD.

`push` does one thing more: after `printable` it replaces `\n` with a literal
`\\n` for the two harness-written kinds. `Call` and `Note` are marked on *every*
row, so a kept break would mint a second marked row from whatever followed it —
which is how a provider error, whose text is the vendor's string verbatim, would
otherwise smuggle a row in.

`invisible` is the bidi-and-zero-width denylist, the same one
[13](13-turn-loop-and-gate.md) meets at the approval prompt: `char::is_control`
is category `Cc` exactly, so U+202E and the directional isolates pass it and a
line can *display* as a different line. The two copies are identical
character-for-character, duplicated rather than shared, and the comment here
says what rides on that: "Duplicates `sandbx-cli`'s `gate::invisible`; the two
sets must not diverge (#233)."

`forgeable` has no counterpart at the prompt, and is this crate's own:

```rust
fn forgeable(c: char) -> bool {
    matches!(
        c,
        GUTTER_MARK | '\u{01c0}' | '\u{2223}' | '\u{2758}' | '\u{ff5c}' | '\u{ffe8}'
        // The bracket and box-line extensions, drawn to tile vertically.
        | '\u{239c}' | '\u{239f}' | '\u{23b8}' | '\u{23b9}'
        // Box drawing's other verticals: heavy, dashed, and the four half-height stubs.
        // Its horizontals are left alone, a table or a `tree` being ordinary output.
        | '\u{2503}' | '\u{2506}' | '\u{2507}' | '\u{250a}' | '\u{250b}'
        | '\u{2575}' | '\u{2577}' | '\u{2579}' | '\u{257b}'
    )
}
```

`GUTTER_MARK` is the first entry in its own denylist, imported from `view.rs` so
the strip and the draw cannot disagree about the character — pinned by
`the_drawn_gutter_is_the_mark_the_transcript_strips`. Everything after it draws
the same cell. Why one pane needs an authenticated row at all is
[15](15-tools-and-the-screen.md)'s argument and
[guide-tui.md](../guide-tui.md)'s.

### The same hazard, three surfaces, three answers

| surface | model text is | why |
|---|---|---|
| `agent-run`'s stdout | verbatim — `render.rs` does `self.write(delta.as_bytes())` | stdout is the deliverable, and [13](13-turn-loop-and-gate.md) prices the trade |
| the `--approve call` question | `gate::stripped`: `\n` and `\t` **spelled** `\\n`/`\\t`, the rest U+FFFD | a heredoc shown as a row of U+FFFD is a command consented to unread |
| a cell | `printable`: `\n` **kept**, `\t` to spaces, the rest U+FFFD, plus `forgeable` | the view needs the break as a split point, and one pane carries two voices |

The weakest handling is on the surface with no screen state to corrupt; the two
that render a claim both strip, and both replace rather than delete for the same
reason — dropped, a hostile string reads as plausible prose. Stripping is
idempotent, so a per-call line stripped by `gate::line` and again at the cell
composes.

- **Worth questioning:** the gutter authenticates sandbx's voice and nothing
  authenticates the operator's. `view::gutter` draws two marks: `│ ` on a
  verdict or a note, `> ` on the prompt's first row. `forgeable` covers the
  first and its confusables; `>` is ASCII and let through deliberately, on
  `GUTTER_MARK`'s own reasoning that "`|` or `>` is plausible in prose, and
  stripping either would mangle shell pipelines". For `|` the trade has a
  backstop — the real mark is a different character, and the guide notes that a
  box-drawing vertical joins across rows where a `|` leaves a gap — and for `>`
  there is none, which is where `guide-tui.md`'s defence of the wrapped row,
  "an unmarked row claims nothing", bites: a continuation row carries no gutter
  and starts in column 0, so a row beginning `> ` renders in the operator's own
  grammar. Weaker than forging a verdict — misattributed authorship rather than
  consent, and the wrap has to land immediately before the mark, which a model
  that cannot see the pane's width can only spray for. Not nothing either, the
  pane being the only record a `bash` call's text gets (#234), and the guide
  already names the fix for the other mark: a gutter in an area of its own.

### Where the tests are, and why they can be here

`Transcript` is a pure fold — events in, entries out, no terminal and no clock —
so the crate's security-relevant file is also the one with real coverage: what
an event becomes is an `assert_eq!` on a `Vec<Entry>`, and the sanitiser is a
free function over `&str`. Inline in
[`transcript.rs`](../../crates/sandbx-tui/src/transcript.rs),
`an_escape_sequence_in_the_answer_does_not_survive_the_fold` folds
`"done\x1b[2Jgone\r\x07"` and asserts the exact replacement, so the `[2J` that
survives as ordinary text is visible in the expectation; two more cover the
reordering characters and the gutter confusables, each asserting
`!c.is_control()` of its own inputs to keep the justification for `invisible`
and `forgeable` inside the test.
[`view.rs`](../../crates/sandbx-tui/src/view.rs) draws state and reads none, so
its tests render into ratatui's `TestBackend` and read cells back as rows of
strings — which is how `an_answer_cannot_forge_the_row_a_verdict_is_drawn_on`
can assert that exactly one row starts with the mark. What no test reaches is
`Screen::enter` and the `event::read` loop — and neither holds a decision, which
is the order to take that in.

## view.rs tail-aligns, and loses nothing it could show

Two areas from one `Layout::vertical`: `Constraint::Min(0)` for the body,
`Constraint::Length(1)` for the status bar. The body is one `Paragraph` with
`Wrap { trim: false }` holding the whole transcript, a blank row between
entries, each row prefixed by its kind's gutter, and styled with `Modifier`s
rather than colours — with no palette a colour falls back to the default
foreground, making a reasoning line and a refusal read alike.

"Tail-aligned" is three lines, and the comment above them is the part to keep.

```rust
    // Auto-follow is measured after wrapping, not counted off entries: a wrapped answer has
    // more rows than newlines, and scrolling by the smaller figure strands the tail off-screen.
    let rows = paragraph.line_count(body.width);
    let scroll = u16::try_from(rows.saturating_sub(usize::from(body.height))).unwrap_or(u16::MAX);

    frame.render_widget(paragraph.scroll((scroll, 0)), body);
```

`line_count` is why the manifest pins ratatui exactly and enables
`unstable-rendered-line-info`: measuring after wrapping is the alternative to a
second word-wrapper that would have to agree with ratatui's to the row.

- **A long line wraps rather than truncating**, a truncated line being
  unrecoverable — no scroll key, no scrollback behind the alternate screen.
  `a_line_wider_than_the_pane_wraps_rather_than_truncating` asserts it, and
  shows the continuation row starting in column 0 with no gutter.
- **The scroll is recomputed from the whole transcript every frame**, so nothing
  is consumed by being drawn and a terminal *grown* mid-turn brings scrolled-off
  rows back on the next repaint. The offset is a `u16` and clamps there.
- **Nothing is lost permanently; it is lost to the operator.** Every entry stays
  in the `Vec` for the `Transcript`'s life, but with auto-follow only no key
  brings a scrolled-off row back, and the alternate screen takes it when it is
  given back — which for a `bash` call is the only place the command's text
  appeared (#234).

The status bar is `rounds N`, the token figures if any arrived, and one `Hint`,
joined with ` · ` and drawn `REVERSED`.

## screen.rs takes the terminal, and `Drop` gives it back

`Screen::enter` calls `ratatui::try_init`, which turns raw mode on and enters
the alternate screen in that order — "so a failed second step leaves the first
in force" — with `inspect_err(|_| ratatui::restore())` to undo a half-done take.
Raw mode is not a convenience: it is what makes ctrl-c arrive at `Keys` as a
`KeyEvent` rather than raising `SIGINT`, which is why `Keys::listen` is started
after `enter` and never before.

Giving it back is the mechanism:

```rust
impl Drop for Screen {
    /// Leave raw mode and the alternate screen, whatever the turn did.
    ///
    /// `Drop`, not a method: an unwinding panic must still restore the terminal, which
    /// `try_init`'s hook covers only earlier. Neither covers `SIGKILL`.
    fn drop(&mut self) {
        ratatui::restore();
    }
}
```

A panic anywhere in the turn — the fold, a gate line, the driver — would
otherwise leave the operator in raw mode with no echo, on an alternate screen,
in a shell that still works and shows nothing it is told. Unwinding runs `Drop`,
so the panic message lands on a usable terminal.

The limit is the comment's last sentence, and it generalises past `SIGKILL`: a
`Drop` impl does not run on `SIGKILL` or `SIGSTOP`, on `std::process::abort` or
a double panic, or in a `panic = "abort"` build. Each leaves the terminal as the
turn left it, `reset` in the shell the only fix — the same shape as the held
audit trail losing everything to a signal that runs no `Drop` (#235).

Two draw methods and a latch. `draw` repaints from the transcript; `redraw`
discards the back buffer first by resizing to the size already in force, since
ratatui flushes only the diff between its two buffers and a cell a third party
wrote would never be rewritten. The comment records the trap: not
`Terminal::clear`, whose cursor query would deadlock against crossterm's single
reader while `Keys` parks it in `event::read`. Both return `()`, the first
`io::Error` latching into `failed` so every later draw is a no-op, and the
caller takes it once:

> The draw failure that stopped the screen updating, if one did. Taken, so a
> caller reports it once — and it must: everything after it happened off-screen,
> and a turn whose tool calls nobody saw was not watched.

The error is available, then, but only by asking: a turn whose screen died in
round one runs on under the policy it was given, every later call drawn into
nothing. No consent is bypassed — `tui` refuses `--approve call` (#225), so its
gate's decision is argv's — and what is lost is the watching. Whether anything
acts on `failure()` before the turn ends is [24](24-crate-cli.md)'s.

## input.rs is a thread, because `event::read` cannot be cancelled

`Keys` is one `watch::Receiver<Seen>`, and `Seen` is a press tally plus a sticky
`stop` flag. `listen` spawns a plain `std::thread` that loops on `event::read`
and sends after each press. Why a thread and not an async task — three reasons
that compose, the first from the module doc:

- **`event::read` cannot be cancelled.** It parks until the next key or process
  exit, holding no state. There is no future to drop.
- **`spawn_blocking` would hang the exit.** A blocking task runs to completion
  once spawned (#26) and `Runtime::drop` waits for an in-flight one with no
  timeout, as [guide-tui.md](../guide-tui.md) records for the `bash` case — so
  parking `event::read` there is a process that cannot exit until somebody
  presses a key. A `std::thread` is not something the runtime waits on.
- **The crate could not spawn a task anyway**, `tokio` being here with `sync`
  alone: a channel, no runtime, no timer.

The reader also holds crossterm's one reader lock while parked, which is the
constraint `Screen::redraw` is written around: anything asking the terminal a
question answered on stdin deadlocks against it.

Which keys end a turn is four lines.

```rust
/// Whether `key` means "stop this turn": ctrl-c, since raw mode took it from the signal it
/// would otherwise raise; and escape, there being no input box for it to leave instead.
fn interrupts(key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Char('c') => key.modifiers.contains(KeyModifiers::CONTROL),
        KeyCode::Esc => true,
        _ => false,
    }
}
```

`an_unmodified_c_does_not` pins that a bare `c`, a shifted `C` and `Enter` do
not — "or the screen is unusable once it takes typed input". Only
`KeyEventKind::Press` counts, Windows also reporting a release per key.

How that intent reaches a loop awaiting a provider stream: it does not reach the
loop at all. `Keys` exposes two futures and the driver races one against the
turn, so the turn loop gains no stop variant and no cancel token — what that
costs is [15](15-tools-and-the-screen.md)'s. Three properties of the channel are
this file's own:

- **`stop` is sticky.** A `watch` keeps one slot, so a later keypress would
  overwrite an unobserved interrupt; `seen.stop |= interrupts(key)` latches
  instead, and `an_interrupt_survives_a_later_keypress` is the test.
- **`stop` never resolves on a dead reader.** When `changed()` errors it awaits
  `std::future::pending()` forever, "since a closed channel must not end a turn
  nobody asked to end".
- **`press` resolves at once on a dead reader**, the deliberate opposite: it
  holds a finished screen until a key arrives, and with none able to arrive,
  waiting would hold the alternate screen until the process was killed.

The thread exits on a send error — the receiver dropped — and on a read error
without retrying, "the descriptor is gone, and looping would spin the thread at
full speed". Resize, mouse, paste and focus events are ignored.

## You should now be able to explain

- Why `sandbx-tui` has no row in 04's table of boundaries, which four names it
  exports, and why `Entry` and `Kind` are not among them.
- What the single internal dependency rules out as a build error, and the two
  things it does not.
- Why a terminal renderer is a sanitisation boundary, in terms of where the text
  in a cell came from, and why that file is also the one with real coverage.
- The four classes `printable` sorts a character into, why `\n` is treated
  differently at the cell than at the approval prompt, and which file holds the
  other copy of the same `invisible` denylist (#233).
- What "tail-aligned" is measured against, and whether a row that scrolled off
  is gone or merely off-screen.
- What `Screen`'s `Drop` impl protects against, and the ways a process can end
  without running it.
- Why the key reader is a `std::thread`, and why `Keys::stop` never resolves on
  a closed channel while `press` resolves at once.

## Next

[24 — the cli crate](24-crate-cli.md), where all of this is driven from:
`cli/src/agent/tui.rs` enters the `Screen`, starts the `Keys`, folds each event
into the `Transcript`, races the turn against the keypress, and draws the gate's
verdicts instead of printing them. It is the largest crate in the workspace, and
the only caller this one has.
