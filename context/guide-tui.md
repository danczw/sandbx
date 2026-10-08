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

Replaced rather than dropped, for `gate.rs`'s reason: dropped, a hostile string
reads as plausible prose.

The per-call line is stripped twice over — `gate::line` strips what the model
chose, including the invisible and the direction-reordering characters the gate's
own denylist covers, and the transcript strips again at the cell. Idempotent, so
the layers compose.

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
  was writing files goes on writing them, unseen.

The exit code is 2 — the same code a turn cut short by `--max-rounds` gets,
because that is what it is.

A stop `tui` has no account of exits 0, an answer being the thing a turn is for.
The exception is a stop that documents a code of its own: `TurnStop::GateAborted`
exits 3, ahead of the bound, because a turn can hit `--max-rounds` and lose its
operator in the same round and only one of those is unrecoverable. Unreachable
while `tui` builds its gate with no operator to ask, and written now because the
outcome holds its messages and usage like an answered one — so a 0 there would
look like an answer to every test and to every caller branching on the status.

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
