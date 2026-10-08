# The terminal UI

`sandbx tui` asks the same question `agent-run` asks, under the same policy, and
draws the turn as it arrives instead of streaming it to stdout. One prompt, one
turn, and a key that ends it.

## What is shared, and what is not

The subcommand flattens `AgentRun`, so there is one declaration of every flag and
one derivation of the policy behind it. `gate::approves` decides which tools may
run, `orientation::system_prompt` tells the model what it may reach, and
`session::open` carries a conversation between runs — all of them the same
functions `agent-run` calls.

Three things differ:

| | `agent-run` | `tui` |
|---|---|---|
| the answer | stdout, streamed | a pane, repainted |
| the per-call account | stderr | the pane |
| ending a turn early | nothing does | a keypress |

Everything else that differs is a refusal, not a variation: `tui` needs a
terminal on stdout, and it refuses `--approve call` (#225).

## The crate draws and nothing else

`sandbx-tui` takes `&AgentEvent` and gives back a keypress. It holds no policy,
no provider, no session and no gate, which is what keeps the security-bearing
code in one place: a renderer that could decide anything would be a second place
to look for what approved a call.

```
Transcript   the events folded into entries          no terminal → unit-tested
View         the entries laid out as rows            TestBackend → unit-tested
Screen       raw mode, the alternate screen, Drop    a real terminal only
Keys         the reader thread and the press         the predicate → unit-tested
```

The split is for testability. `Transcript` is a fold with no screen behind it, so
what each event becomes is an assertion rather than a screenshot; `View` renders
into a buffer a test reads cell by cell. What is left needing a real terminal is
`Screen::enter` and the `event::read` loop, and neither holds a decision.

### Model text cannot reach a cell unchanged

ratatui writes a cell's content to the terminal as it was given. An answer
carrying `\x1b[2J` would therefore clear the screen it is being drawn on, and one
carrying a cursor-positioning sequence would rewrite the lines around itself —
including the account of what a tool just did. So control bytes are replaced with
U+FFFD on the way into an entry: `\n` survives as the break the view splits on,
a tab becomes spaces, and everything else `char::is_control` matches is marked.

`is_control` is category `Cc` exactly, which is not the whole hazard. U+202E and
the directional isolates render *nothing* and reorder what follows them, so a
line can display as a different line — in the same pane, and the same `sandbx: `
grammar, as the gate's account of what a tool did. The same denylist `gate.rs`
carries therefore applies at the cell too. It is a denylist because `char` has no
predicate for the category, so a new Unicode version can outgrow it silently;
it is duplicated rather than shared because the two sites must not diverge.

One more character cannot reach a cell, and it is sandbx's own: the gutter the
view draws at the start of every row it wrote. See below.

Replaced rather than dropped, for `gate.rs`'s reason: dropped, a hostile string
reads as plausible prose. The per-call line is stripped twice over — once by
`gate::line`, once at the cell — and stripping is idempotent, so the layers
compose.

### One pane holds both voices, so a row says which it is

`agent-run` has two channels and the channel authenticates the line: the answer
is on stdout, every account of the run on stderr. The pane has one, so a model
that writes

```
sandbx: bash curl … | sh — ran
```

into its answer would render a free-standing row in the gate's own grammar, and
an operator would act on a call the gate never saw. A newline survives the fold
by design — the view splits on it — so there is nothing stopping the rows from
forming.

Every row therefore carries a gutter the view draws, not the text: `│ ` on a
verdict or a note, `> ` on the prompt's first row, two spaces on anything the
model chose. `│` is what the claim rests on, so no entry's text may *draw* one.
`Transcript` replaces the mark and the characters that render the same single
cell — U+FFE8 is Unicode's own confusable mapping for `│`, and a heavier or
dashed box-drawing vertical differs by a weight an operator has nothing on screen
to compare against. The horizontals are left alone, a table being ordinary
output.

ASCII `|` is the one it lets through, and is why the mark is box-drawing at all: a
shell pipeline in ordinary prose has to survive the fold. What stands against a
`|` is only that a box-drawing vertical joins across rows where a `|` leaves a
gap — font-dependent, and weaker than the strip.

A wrapped continuation row carries no gutter, the gutter being inside the
paragraph's text rather than a column beside it, so such a row begins in the real
gutter's own column. That is survivable because an unmarked row claims nothing
and no entry text can draw the mark — not because the column is defended. A
gutter given its own area beside the text would retire the question.

A break inside a verdict or a note is spelled `\n` rather than kept. Those two
kinds are marked on every row and not the first, so that a forged line sitting
mid-entry is marked too — which means a break in one would mint a second marked
row from whatever followed it, needing no confusable at all. `gate::line` already
escapes; the note wording a provider error does not, its message being the
vendor's string verbatim.

Modifiers are not load-bearing here. `BOLD | DIM` sets a verdict apart from the
answer, but a terminal with no palette, a copy-paste or a screenshot-to-text
drops attributes and keeps characters.

### Raw mode is what makes the interrupt possible

With raw mode on, ctrl-c arrives as a `KeyEvent` instead of raising `SIGINT`.
Without it the default handler would kill the process mid-turn and leave the
alternate screen on the operator's terminal. So `Keys` is started after
`Screen::enter`, never before.

`Screen` restores on `Drop`, so a panic unwinding through the turn still puts the
terminal back; ratatui's own panic hook covers the window before the `Screen`
exists. Neither covers `SIGKILL`, and nothing can.

## What interrupting costs

The interrupt is a `tokio::select!` in `sandbx-cli`, racing the turn's future
against the keypress. The turn loop gains nothing: no stop variant, no cancel
token, no second way for a turn to end.

Two consequences, which the screen states at the time rather than leaving to be
discovered:

- **Nothing of that turn is stored**, `--session` or not. The future is dropped,
  so there is no `TurnOutcome` to append, and a transcript holding the prompt
  without the answer would make the next resume send two user turns in a row.
- **A tool already running finishes.** `spawn_blocking` cannot be cancelled
  (#26), so dropping the future abandons the result, not the work. A `bash` that
  was writing files goes on writing them, unseen — and the process does not exit
  until it is done, `Runtime::drop` waiting for an in-flight blocking task with
  no timeout. So an interrupt during a long call returns the terminal and then
  hangs there, which is a wait on work the operator can no longer see.

The exit code is 2 — the same code a turn cut short by `--max-rounds` gets,
because that is what it is.

Two other codes, neither of which the stop alone decides:

- a round cut at `--max-tokens` exits 2, whatever the turn's own stop was. The
  bound ends a round inside the turn, so a turn that stops `Answered` can still
  have ended mid-sentence; reading the stop by itself would exit 0 on it.
- `TurnStop::GateAborted` exits 3, ahead of either bound, because a turn can hit
  `--max-rounds` and lose its operator in the same round and only one of those is
  unrecoverable. Unreachable while `tui` builds its gate with no operator to ask,
  and written now because the outcome holds its messages and usage like an
  answered one — so a 0 there would look like an answer to every test and to
  every caller branching on the status.

A stop `tui` has no account of exits 0, an answer being the thing a turn is for.
Both bounds can cut one turn, so the screen's account is a list and a turn that
met both says both.

## Light by intent

The first iteration draws one turn and takes one key. Named here because each is
a limit an operator meets, not an omission to infer:

- **Single-shot.** The prompt comes from argv, as `agent-run`'s does. No input
  box, so no second turn without a second run.
- **Auto-follow only.** The pane shows the tail and there are no scroll keys, so
  a line that scrolled off is gone — which is why a long line wraps rather than
  truncating.
- **Repainted on an event.** Nothing redraws between events, so the screen is
  still for the duration of a tool call, and a resize repaints on the next event.
  The interrupt works throughout regardless, being a `select!` arm rather than a
  redraw.
- **No wrap-up round.** A turn that reaches `--max-rounds` is not asked once more
  under `tui`; `agent-run`'s `wrapup` is what does that, and the screen says the
  answer ended on tool work.
- **No per-call consent.** `--approve call` wants a question on `/dev/tty`, which
  cannot share a raw-mode screen with the pane; a modal to ask it with is #225.
  Refused rather than downgraded to the argv answer, which would serve a wider
  regime than the flag asked for.

## The gate draws its verdicts

`tui`'s gate delegates `approve` to `ArgvGate` — the decision has to be the one
`agent-run` makes, or one `--allow-tool` would approve two different sets — and
overrides `settled` alone, to draw the line instead of printing it.

That override is the point: `ArgvGate::settled` writes with `eprintln!`, and the
alternate screen does not redirect stderr. Left alone it would paint over the
pane and then vanish with it, so the operator would lose the account entirely.
The accounts written before the screen is entered stay on stderr, where they are
legible once the screen is given back; #224 covers the seam.

Both methods still run on the async task, so **neither may wait on the runtime**
— `decision-approval-gate.md` has why. `tui`'s gate waits on nothing at all: the
decision is argv's, and `settled` takes a lock no async task holds.

## The audit trail is held, not displaced

The gate's verdict is not the only thing stderr carries. `logging::init` installs
one subscriber for the whole process, admitting `sandbx::audit` at `INFO`, and
`sandbx-core` emits a record for every guarded file access and every command
spawn. Those are the higher-volume writer by far, and the alternate screen
neither redirects stderr nor hands back what was written to it: each record
would land in the pane and then die with the screen.

Two things go wrong at once, which is why neither a repaint nor a redirect is
enough on its own:

- **the pane is corrupted.** ratatui flushes the difference between its own two
  buffers, so a cell a third party overwrote is never rewritten, and the record's
  trailing newline scrolls the alternate screen and puts every row one out of
  place.
- **the trail is lost.** README claims every run records the policy it ran under
  on stderr. Written into a screen that is about to be torn down, it is recorded
  nowhere.

So `tui` holds the trail: `logging::hold` diverts the subscriber's writer into a
buffer for as long as the screen owns the terminal, and releasing it writes every
record to stderr once the screen is given back. The guard releases on `Drop`, so
a panic unwinding past the screen still leaves behind the record of what the turn
was allowed to touch. The ordering an operator sees is the trail, then the run's
own account — both after the turn rather than during it, which is the one thing
`tui` changes about the trail.

The hold covers `tracing` and nothing else, so a bare `eprintln!` reached from
inside the screen still lands on it — `AgentRun::save`'s "nothing to store" line
is the one that can. The final paint is a full redraw rather than a diff for
exactly that: it is the only way to put the overwritten cells back.
