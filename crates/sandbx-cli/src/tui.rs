//! `sandbx tui`: one prompt, one turn, drawn on a screen a keypress can stop.
//!
//! Every flag, the policy and the session are `agent-run`'s; what differs is where the
//! turn is reported and that an operator can end one mid-flight. `--approve call` asks on
//! the screen, in `modal`, and no line of the account reaches the stderr the screen covers:
//! the transcript is printed once the screen is given back, the alternate screen keeping
//! nothing it showed (#224).
//!
//! The drawing crates — `sandbx-tui-transcript`, `sandbx-screen` and `sandbx-tui-input` —
//! take events and give back keys, and hold no policy, provider, session or gate: a renderer
//! that could decide anything would be a second place to look for what approved a call.
//! `deny.toml` refuses them a provider edge (#365).
//!
//! Light by intent, each a limit an operator meets: single-shot, the prompt from argv;
//! auto-follow with no scroll keys, so a line that scrolled off is back only in the
//! reprint; repainted only on an event, so the screen is still for a tool call.

use std::io::{self, Write};
use std::mem;
use std::sync::Mutex;

use sandbx_anthropic::AnthropicClient;
use sandbx_approval::{ApprovalDecision, CallGate, Settled, ToolCall};
use sandbx_prompt::{ContentBlock, Prompt, RequestMessage, Role, Thinking};
use sandbx_provider::{EventStream, ProviderError};
use sandbx_screen::{Screen, Transcript};
use sandbx_session_bridge as session;
use sandbx_session_message::TurnStop as StoredStop;
use sandbx_session_store::Session;
use sandbx_tools::{BuiltinTool, ExecutionContext};
use sandbx_tui_input::{Answers, Keys, Stopped};
use sandbx_turn::{Turn, TurnError, TurnOutcome, TurnStop, run_turn_until};

use super::modal::{Modal, Shows};
use super::prompt::{Notes, Stderr, account};
use super::render::{Answer, Unfinished};
use super::{
    AgentRun, Approve, Device, INCOMPLETE, NO_CONSENT, gate, orientation, stored_stop, wrapup,
};
use crate::AgentError;

/// `sandbx tui [--allow-…] -- <prompt>`
#[derive(Debug, clap::Args)]
pub struct Tui {
    // Flattened rather than re-declared: one flag meaning two things across two
    // subcommands is how a policy gets narrower on one of them and nobody notices.
    #[command(flatten)]
    run: AgentRun,
}

impl Tui {
    /// Draw one turn, and report the code to exit with.
    ///
    /// # Errors
    ///
    /// [`AgentError::NotATerminal`] lands after only [`AgentError::EmptyPrompt`], before the
    /// policy and the credential. The rest are [`AgentRun::execute`]'s, plus
    /// [`AgentError::Screen`].
    pub async fn execute(&self) -> Result<i32, AgentError> {
        let prompt = self.run.to_prompt();
        if prompt.trim().is_empty() {
            return Err(AgentError::EmptyPrompt);
        }

        // Before the policy: the refusal needs none, and a run that cannot be drawn must not
        // read a credential on the way to finding that out.
        self.drawable(Device::of(&io::stdout()))?;

        let mut approved = vec![gate::approved_line(self.run.allow_tool.as_deref())];
        if matches!(self.run.approve, Approve::Call) {
            // Said as `agent-run` says it, where the question will be: an inert flag
            // announced as active would be false, and silence would read as consent.
            approved.push(gate::asking_line(
                self.run.allow_tool.as_deref(),
                "on this screen",
            ));
        }
        // Before the screen as well as on it, so a redirected log has them ahead of every call
        // they approved. Not on a terminal stderr, where the reprint already carries them.
        if Device::of(&io::stderr()) == Device::Redirected {
            for line in &approved {
                Stderr.note(line);
            }
        }

        // Ahead of the policy, for `AgentRun::execute`'s reason and with its trade: nothing
        // may sit between the vet and the pin, and this call writes a directory and can
        // block on stderr. The pane being the only place a command's text was drawn is why
        // this path in particular needs the id on the trail.
        let session = session::open(self.run.session())?;

        let policy = self.run.policy()?;
        let system =
            orientation::system_prompt(&policy, self.run.allow_tool.as_deref(), self.run.system());
        // Adjacent to the vet above, for `AgentRun::execute`'s reason: what is between them
        // resolves paths but cannot be stalled.
        let ctx = match session.as_ref() {
            Some(open) => ExecutionContext::for_session(policy, open.id().to_string()),
            None => ExecutionContext::new(policy),
        };

        let client = AnthropicClient::new(sandbx_auth::api_key()?)?;

        self.drive(
            |request| client.stream_chat(request),
            &ctx,
            prompt,
            system,
            &approved,
            session,
        )
        .await
    }

    /// Whether this run can be drawn at all.
    ///
    /// `stdout` is passed in rather than read here: under `cargo test` file descriptor 1 is
    /// still the developer's own terminal, so a check that read it would answer differently
    /// depending on where the tests were run.
    ///
    /// # Errors
    ///
    /// [`AgentError::NotATerminal`] where stdout is not one.
    fn drawable(&self, stdout: Device) -> Result<(), AgentError> {
        if stdout == Device::Redirected {
            return Err(AgentError::NotATerminal);
        }

        Ok(())
    }

    /// Run one turn against `open`, drawing it, and save it to `session`.
    ///
    /// The stream opener is an argument for the same reason it is on
    /// [`AgentRun::drive`](super::AgentRun): it is the only way to drive a turn without a
    /// key.
    async fn drive(
        &self,
        mut open: impl AsyncFnMut(Prompt) -> Result<EventStream, ProviderError>,
        ctx: &ExecutionContext,
        prompt: String,
        system: Option<String>,
        approved: &[String],
        session: Option<Session>,
    ) -> Result<i32, AgentError> {
        let mut transcript = Transcript::new(&prompt, self.run.reasoning());
        for line in approved {
            transcript.note(line);
        }

        let asked = RequestMessage {
            role: Role::User,
            content: vec![ContentBlock::Text { text: prompt }],
        };

        let mut history = session.as_ref().map_or_else(Vec::new, |session| {
            session::request_history(session.messages())
        });
        history.push(asked.clone());
        let merged =
            session::merge_user_runs(history, session.as_ref().map_or(0, Session::withheld));

        let turn = Turn {
            model: self.run.model().to_string(),
            max_output_tokens: self.run.max_tokens(),
            system,
            tools: &BuiltinTool::ALL,
            tool_choice: None,
            thinking: self.run.show_thinking.then_some(Thinking::Visible),
            history: &merged.history,
            limits: self.run.limits(),
            observed: session
                .as_ref()
                .and_then(Session::observed)
                .map(session::request_usage),
            withheld: merged.withheld,
        };

        // Before the screen: a record written once it is up lands in the pane and dies
        // with it.
        let shown = Device::of(&io::stderr());
        let audit = held(shown);

        // The screen before the keys: without raw mode ctrl-c is a signal, and the reader
        // would never see the key that is supposed to stop the turn. One lock because the
        // turn hands out two writers, `observe` and the gate's `settled`, that meet at the
        // same transcript; a `Mutex`, not a `RefCell`, so the turn's future stays `Send`.
        // The approved lines are in `said` only where `execute` did not already write them, so
        // a reprint that fails still leaves them on a terminal stderr.
        let pane = Mutex::new(Pane {
            screen: Screen::enter(transcript).map_err(AgentError::Screen)?,
            said: match shown {
                Device::Terminal => approved.to_vec(),
                Device::Redirected => Vec::new(),
            },
            running: Running::default(),
            over: false,
        });
        let mut keys = Keys::listen();
        paint(&pane, |_| {});

        // Only under `--approve call`: without it argv is the whole answer and nothing is
        // asked. Built after the keys, being what its answers are read from.
        let modal =
            matches!(self.run.approve, Approve::Call).then(|| Modal::new(&pane, keys.answers()));

        // Inside the loop rather than raced against it, so the rounds before the stop come
        // back to be stored. A running tool still finishes, and the process waits on it,
        // `Runtime::drop` having no timeout (#26).
        let mut seen = None;
        let first = run_turn_until(
            &mut open,
            turn.clone(),
            ctx,
            |event| paint(&pane, |transcript| transcript.event(event)),
            Gate {
                argv: gate::ArgvGate::new(self.run.allow_tool.as_deref(), modal),
                pane: &pane,
            },
            async { seen = Some(keys.stop().await) },
        )
        .await;

        let driven = match first {
            Err(error) => Driven::Failed(error),
            Ok(first) => match first.stop {
                TurnStop::Interrupted => Driven::Stopped(
                    seen.expect("only the keys resolve the stop that interrupted the turn"),
                    first,
                ),
                TurnStop::RoundLimit { rounds } if !self.run.no_wrap_up => {
                    // Ahead of the request: the status bar counts this round too, and would
                    // otherwise read one past `--max-rounds` with nothing saying why.
                    (&pane).note(&format!(
                        "sandbx: out of rounds after {}; asking once more, with no tool",
                        counted(rounds)
                    ));

                    // A stop of its own and not the first round's: the turn before it has
                    // finished, so a stop here costs the wrap-up's prose and nothing else.
                    let wrapped = tokio::select! {
                        wrapped = wrapup::run(
                            &mut open,
                            ctx,
                            turn,
                            &first,
                            |event| paint(&pane, |transcript| transcript.event(event)),
                            |call| (&pane).note(&gate::line(call)),
                        ) => Ok(wrapped),
                        stopped = keys.stop() => Err(stopped),
                    };
                    match wrapped {
                        Ok(wrapped) => {
                            let (outcome, ending) = wrapped.finish(first, rounds, &mut &pane);
                            Driven::Finished(outcome, Some(ending))
                        }
                        Err(stopped) => Driven::StoppedWrapping(stopped, first, rounds),
                    }
                }
                TurnStop::RoundLimit { rounds } => {
                    Driven::Finished(first, Some(Unfinished::CutShort(rounds)))
                }
                _ => Driven::Finished(first, None),
            },
        };

        // The borrows the two seams held end with the futures above. Every paint ran on this
        // task, so one that panicked would have unwound past here already.
        let mut pane = pane
            .into_inner()
            .expect("a paint that panicked unwinds past this frame");

        // Noted from here on and never drawn: the screen is about to go, and a paint here is
        // a write that can stall on a paused terminal while the trail is still held.
        pane.over = true;

        let (code, outcome, closing) = match accounted(driven, mem::take(&mut pane.running)) {
            Ok(Accounted { code, kept, said }) => (Ok(code), kept, said),
            Err(error) => {
                // In the reprint only where stderr went elsewhere: `main` prints the error
                // once it is returned, which a terminal would otherwise read twice.
                if shown == Device::Redirected {
                    let line = format!("sandbx: {}", crate::error_line(&error));
                    pane.screen.amend(|transcript| transcript.note(&line));
                }
                (Err(AgentError::from(error)), None, Vec::new())
            }
        };

        for line in &closing {
            pane.note(line);
        }

        // Not `?`: a store that refused the turn must still leave the transcript and the
        // trail, the answer being on the screen and nowhere else.
        let saved = match (outcome, session) {
            (Some((outcome, stop)), Some(session)) => self
                .run
                .save(session, &asked, outcome, stop, &merged, &mut pane),
            _ => Ok(()),
        };
        let code = saved.and(code);

        let Pane {
            mut screen, said, ..
        } = pane;
        let failed = screen.failure();
        let printed = screen.plain();
        drop(screen);

        // A held trail is released the moment there is a stderr with no screen over it, and
        // ahead of the reprint: a stdout the terminal has paused would hold the trail behind
        // it, and a signal there would lose it (#224).
        drop(audit);

        given_back(
            code,
            failed,
            &printed,
            &said,
            shown,
            &mut io::stdout(),
            &mut io::stderr(),
        )
    }
}

/// The hold a turn takes on the audit trail, or `None` where stderr is not a terminal.
///
/// The alternate screen neither redirects a terminal stderr nor gives back what was
/// written to it, so a record would land in the pane and die with it. Any terminal is
/// held, not only the one drawn on. Anything else gets each record as it is emitted,
/// where a signal cannot take it back (#485).
fn held(stderr: Device) -> Option<sandbx_logging::Held> {
    (stderr == Device::Terminal).then(sandbx_logging::hold)
}

/// What the turn's futures came to, before any of it is accounted for.
enum Driven {
    /// Stopped before the turn had finished, which keeps the rounds before the one it
    /// stopped in.
    Stopped(Stopped, TurnOutcome),
    /// Stopped in the wrap-up round of a turn that ran out after `usize` rounds, which is
    /// kept as the cap left it.
    StoppedWrapping(Stopped, TurnOutcome, usize),
    Finished(TurnOutcome, Option<Unfinished>),
    Failed(TurnError),
}

/// What a turn that did not fail keeps, the code it exits with, and every line accounting
/// for both.
struct Accounted {
    code: i32,
    /// The turn `save` is handed and how it is stored, `None` where nothing of it is kept.
    kept: Option<(TurnOutcome, StoredStop)>,
    said: Vec<String>,
}

/// Account for what the turn's futures came to, `running` being the call a stop stood on.
///
/// Apart from `drive` so what a stop keeps is an assertion: the screen it is drawn on needs
/// a terminal, and `SECURITY.md` claims the difference.
fn accounted(driven: Driven, running: Running) -> Result<Accounted, TurnError> {
    Ok(match driven {
        Driven::Stopped(stopped, outcome) => {
            let Ending { code, said } = stop(stopped, false);
            // The call the dropped round stood on never settles, so this is the only line
            // it gets.
            Accounted {
                code,
                kept: Some((outcome, stored(stopped))),
                said: said.into_iter().chain(running.stopped()).collect(),
            }
        }
        // The cap's own lines too, as the same turn stored under `--no-wrap-up` has them. The
        // stop's code stands: the cap's is 2, and a hangup's 3 must not be lowered by it.
        Driven::StoppedWrapping(stopped, first, rounds) => {
            let unfinished = Some(Unfinished::CutShort(rounds));
            let Ending { code, mut said } = stop(stopped, true);
            said.extend(ending(&first, unfinished).said);
            let stored = stored_stop(first.stop, unfinished);
            Accounted {
                code,
                kept: Some((first, stored)),
                said,
            }
        }
        Driven::Finished(outcome, unfinished) => {
            let Ending { code, said } = ending(&outcome, unfinished);
            let stop = stored_stop(outcome.stop, unfinished);
            Accounted {
                code,
                kept: Some((outcome, stop)),
                said,
            }
        }
        Driven::Failed(error) => return Err(error),
    })
}

/// How a stop is stored, a hangup apart from a keypress for [`stop`]'s reason.
fn stored(stopped: Stopped) -> StoredStop {
    match stopped {
        Stopped::Pressed => StoredStop::Interrupted,
        Stopped::Gone => StoredStop::HungUp,
    }
}

/// The code a stop exits with, and its line. `wrapping` is whether it found the turn in
/// its wrap-up round, which keeps every round before it, where any other stop loses the
/// round it lands in.
///
/// A hangup has its own line and not the interrupt's: the operator did not stop this turn,
/// and telling them they did is the one reading of a hangup that is certainly wrong (#264).
/// It exits 3 and not 2, the code a lost gate already takes: a turn nobody could see is one
/// nobody watched, and that is not the recoverable stop an interrupt is.
fn stop(stopped: Stopped, wrapping: bool) -> Ending {
    let (code, how) = match stopped {
        Stopped::Pressed => (INCOMPLETE, "sandbx: interrupted"),
        Stopped::Gone => (
            NO_CONSENT,
            "sandbx: the terminal went away, so the turn stopped where it stood",
        ),
    };
    // Not "stored": nothing is without `--session`, and `save` has not run yet. No tool
    // call to name in the wrap-up round, its gate letting none run.
    let what = if wrapping {
        format!(
            "{how} in the wrap-up round. What it wrote is lost; under `--session`, the turn \
             before it is kept as the cap left it"
        )
    } else {
        format!(
            "{how}. Under `--session` the rounds it finished are kept and the one it stopped \
             in is lost, and a tool call already running finishes unseen: the process waits \
             for it before it exits (#26)"
        )
    };

    Ending {
        code,
        said: vec![what],
    }
}

/// `rounds` with its noun, so a cap of one does not read as "1 rounds".
fn counted(rounds: usize) -> String {
    match rounds {
        1 => "1 round".to_string(),
        n => format!("{n} rounds"),
    }
}

/// Write what the run has to say on a terminal the screen has given back, and report the
/// code.
///
/// `printed`, the transcript, first and always: the alternate screen took every row with
/// it, the answer and every line in `said` among them. `said` again where `shown` is
/// redirected or the reprint could not be written, a failed turn owing it as much as a
/// finished one. A latched draw failure is one more line and not the code: the code answers
/// what the turn did, which a failed draw is not (#257). `agent-run` does the opposite with
/// a stdout it could not write, that being the channel the answer came back on. The writers
/// are arguments so the order is a unit test.
///
/// `write!` and not `eprintln!`: when the screen was the terminal that hung up, both are
/// the same dead descriptor, and a panicking macro here would lose the code the turn earned
/// (#264).
fn given_back(
    code: Result<i32, AgentError>,
    failed: Option<io::Error>,
    printed: &str,
    said: &[String],
    shown: Device,
    out: &mut impl Write,
    err: &mut impl Write,
) -> Result<i32, AgentError> {
    let reprinted = out
        .write_all(printed.as_bytes())
        .and_then(|()| out.flush())
        .is_ok();

    if shown == Device::Redirected || !reprinted {
        for line in said {
            // Through `account`, for the reset a terminal stderr is owed.
            let _ = err.write_all(account(shown, line).as_bytes());
        }
    }

    // After the account: a failed turn's own error is the last line, and `main`'s.
    let code = code?;

    // Through the variant and `error_line`, so the line is the one `main` would have
    // printed had this stayed the return value.
    if let Some(error) = failed {
        let _ = writeln!(
            err,
            "sandbx: {}",
            crate::error_line(&AgentError::Screen(error))
        );
    }

    Ok(code)
}

/// The code a finished turn exits with, and every line accounting for it.
///
/// `unfinished` is what became of a turn out of rounds, `None` for any other. Apart from
/// the drawing so the code is an assertion rather than a screenshot: a `GateAborted`
/// outcome holds its messages and its usage like an answered one, so nothing but the code
/// tells a caller the operator went away. A list and not a line, because two bounds can cut
/// one turn: `--max-rounds` ends the turn and `--max-tokens` ends a round inside it.
fn ending(outcome: &TurnOutcome, unfinished: Option<Unfinished>) -> Ending {
    // Not `account`: CodeQL's `rust/cleartext-logging` reads that name as a credential and
    // flags every assert that prints this list (#461). Rename back once it stops matching.
    let mut said = Vec::new();

    // Every cap variant exits 2, as under `agent-run`: the tool work was cut off whatever
    // prose followed it.
    let code = match (outcome.stop, unfinished) {
        // Ahead of the bounds, as `Render::finish` has it: one turn can hit `--max-rounds`
        // and lose its operator, and only the second is unrecoverable.
        (TurnStop::GateAborted, _) | (_, Some(Unfinished::Aborted)) => {
            said.push(
                "sandbx: the gate could no longer be asked, so the turn stopped where it \
                 was asked. That call and every call behind it were refused, and nothing \
                 further was sent"
                    .to_string(),
            );
            NO_CONSENT
        }
        (_, Some(Unfinished::Summarised(rounds))) => {
            said.push(format!(
                "sandbx: the answer above summarises what {} of tool calls found; raising \
                 `--max-rounds` would let the turn go further",
                counted(rounds)
            ));
            INCOMPLETE
        }
        (_, Some(Unfinished::Discarded(rounds))) => {
            said.push(format!(
                "sandbx: out of rounds after {}; what the wrap-up round wrote is not an \
                 answer, and is not stored. Raising `--max-rounds` would let the turn go further",
                counted(rounds)
            ));
            INCOMPLETE
        }
        (_, Some(Unfinished::CutShort(rounds))) | (TurnStop::RoundLimit { rounds }, None) => {
            said.push(format!(
                "sandbx: out of rounds after {}, so the answer ends on tool work; raising \
                 `--max-rounds` would let the turn go further",
                counted(rounds)
            ));
            INCOMPLETE
        }
        // Not matched exhaustively: a stop this does not know about is an answer it has no
        // account of. One documenting an exit code of its own needs an arm above, or `tui`
        // contradicts a code `agent-run` already claims.
        _ => 0,
    };

    // Read whatever the stop was: the round carrying the reply can be cut at `--max-tokens`
    // on its own, which is an answer stopping mid-sentence and must not exit 0.
    if Answer::of(outcome.round_stop.as_ref()) == Answer::Truncated {
        said.push(
            "sandbx: the answer stops at `--max-tokens`, mid-sentence and not at the \
             model's own end of turn"
                .to_string(),
        );

        // Never over a code already chosen: a turn can lose its operator and be cut in the
        // same round, and the cut is the recoverable one.
        return Ending {
            code: if code == 0 { INCOMPLETE } else { code },
            said,
        };
    }

    Ending { code, said }
}

/// What [`ending`] makes of a finished turn.
#[derive(Debug, PartialEq, Eq)]
struct Ending {
    code: i32,
    /// Every line accounting for `code`, in the order they are drawn. Named as [`ending`]'s
    /// local is, for the reason given there.
    said: Vec<String>,
}

/// The screen, and the account noted on it.
struct Pane {
    screen: Screen,
    /// Every line of the account, in order, for a stderr the reprint does not reach.
    said: Vec<String>,
    running: Running,
    /// Whether the turn is over, after which a line is noted and not drawn.
    over: bool,
}

impl Notes for Pane {
    /// Into the transcript, and kept: the screen takes the line with it when it goes.
    fn note(&mut self, line: &str) {
        let change = |transcript: &mut Transcript| transcript.note(line);
        if self.over {
            self.screen.amend(change);
        } else {
            self.screen.paint(change);
        }
        self.said.push(line.to_string());
    }
}

/// The call the gate let through and that has not settled yet.
///
/// Apart from [`Pane`] so a test can drive it without a screen.
#[derive(Default)]
struct Running(Option<String>);

impl Running {
    /// Set on `Allow` alone: a refused call settles before anything runs.
    fn approved(&mut self, call: ToolCall<'_>, verdict: &ApprovalDecision) {
        if matches!(verdict, ApprovalDecision::Allow) {
            self.0 = Some(gate::describe(call.tool, call.input));
        }
    }

    fn settled(&mut self) {
        self.0 = None;
    }

    /// The line a stop owes the call it stood on, if one was running.
    fn stopped(self) -> Option<String> {
        self.0.map(|call| {
            format!("sandbx: {call} — still running when the turn stopped, and finishes unseen")
        })
    }
}

/// The pane as the seams share it: a line is noted as [`paint`] draws, not at all under a
/// poisoned lock.
impl Notes for &Mutex<Pane> {
    fn note(&mut self, line: &str) {
        if let Ok(mut pane) = self.lock() {
            pane.note(line);
        }
    }
}

/// Change the transcript and redraw, or do nothing at all.
///
/// A poisoned lock is a panic already unwinding, whose terminal `Screen::drop` is about to
/// restore; panicking again here would replace that account with this one.
fn paint(pane: &Mutex<Pane>, change: impl FnOnce(&mut Transcript)) {
    if let Ok(mut pane) = pane.lock() {
        pane.screen.paint(change);
    }
}

/// The question goes on the screen: drawn as [`paint`] draws, and reported undrawn under a
/// poisoned lock, once a draw has failed, or in a window too small to show it.
impl Shows for &Mutex<Pane> {
    fn show(&mut self, lines: &[&str]) -> bool {
        paint(self, |transcript| transcript.ask(lines));
        self.lock()
            .is_ok_and(|pane| pane.screen.drawing() && pane.screen.shows_question())
    }

    fn clear(&mut self) {
        paint(self, Transcript::answered);
    }
}

/// The gate `tui` drives: argv decides, an operator may narrow it on the screen, and every
/// call is drawn.
struct Gate<'a> {
    /// `agent-run`'s gate, asking on the screen under `--approve call` and nobody
    /// otherwise. Delegated to whole, which is what keeps argv's answer one answer.
    argv: gate::ArgvGate<'a, Modal<&'a Mutex<Pane>, Answers>>,
    pane: &'a Mutex<Pane>,
}

impl CallGate for Gate<'_> {
    /// Delegated, never re-derived: one `--allow-tool` approving two different sets across
    /// two subcommands is the divergence nobody notices until a `bash` runs.
    fn approve(&mut self, call: ToolCall<'_>) -> ApprovalDecision {
        let verdict = self.argv.approve(call);
        if let Ok(mut pane) = self.pane.lock() {
            pane.running.approved(call, &verdict);
        }
        verdict
    }

    /// The same line `agent-run` writes, through the pane: `ArgvGate::settled` puts it on
    /// stderr, which the alternate screen neither redirects nor gives back.
    fn settled(&mut self, call: Settled<'_>) {
        let line = gate::line(call);
        if let Ok(mut pane) = self.pane.lock() {
            pane.running.settled();
            pane.note(&line);
        }
    }
}

#[cfg(test)]
#[path = "tui_tests.rs"]
mod tests;
