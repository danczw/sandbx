//! `sandbx tui`: one prompt, one turn, drawn on a screen a keypress can stop.
//!
//! Every flag, the policy and the session are `agent-run`'s; what differs is where the
//! turn is reported and that an operator can end one mid-flight. `--approve call` is
//! refused rather than downgraded (#225), and no line of the account reaches the stderr the
//! screen covers: the transcript is printed once the screen is given back, the alternate
//! screen keeping nothing it showed (#224).
//!
//! The drawing crates — `sandbx-tui-transcript`, `sandbx-screen` and `sandbx-tui-input` —
//! take events and give back keys, and hold no policy, provider, session or gate: a renderer
//! that could decide anything would be a second place to look for what approved a call.
//! `deny.toml` refuses them a provider edge (#365).
//!
//! Light by intent, each a limit an operator meets: single-shot, the prompt from argv;
//! auto-follow with no scroll keys, so a line that scrolled off is back only in the
//! reprint; repainted only on an event, so the screen is still for a tool call; no wrap-up
//! round (#232).

use std::io::{self, Write};
use std::mem;
use std::sync::Mutex;

use sandbx_anthropic::AnthropicClient;
use sandbx_approval::{ApprovalDecision, CallGate, Settled, ToolCall};
use sandbx_prompt::{ContentBlock, Prompt, RequestMessage, Role, Thinking};
use sandbx_provider::{EventStream, ProviderError};
use sandbx_screen::{Screen, Transcript};
use sandbx_session_bridge as session;
use sandbx_session_store::Session;
use sandbx_tools::{BuiltinTool, ExecutionContext};
use sandbx_tui_input::{Keys, Stopped};
use sandbx_turn::{Turn, TurnLimits, TurnOutcome, TurnStop, run_turn};

use super::prompt::{Notes, Stderr};
use super::render::Answer;
use super::{AgentRun, Approve, Device, INCOMPLETE, NO_CONSENT, Terminal, gate, orientation};
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
    /// Draw one turn, and report the code to exit with. `ending` decides which.
    ///
    /// # Errors
    ///
    /// [`AgentError::NotATerminal`] and [`AgentError::ApproveUnderTui`] land before anything
    /// else, including before the credential is read. The rest are
    /// [`AgentRun::execute`]'s, plus [`AgentError::Screen`].
    pub async fn execute(&self) -> Result<i32, AgentError> {
        let prompt = self.run.to_prompt();
        if prompt.trim().is_empty() {
            return Err(AgentError::EmptyPrompt);
        }

        // Before the policy: neither refusal needs one, and a run that cannot be drawn
        // must not read a credential on the way to finding that out.
        self.drawable(Device::of(&io::stdout()))?;

        let approved = gate::approved_line(self.run.allow_tool.as_deref());
        // Before the screen as well as on it, so a redirected log has it ahead of every call
        // it approved. Not on a terminal stderr, where the reprint already carries it.
        if Device::of(&io::stderr()) == Device::Redirected {
            Stderr.note(&approved);
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
    /// `terminal` is whether stdout is one, passed in rather than read here: under
    /// `cargo test` file descriptor 1 is still the developer's own terminal, so a check
    /// that read it would answer differently depending on where the tests were run.
    ///
    /// # Errors
    ///
    /// [`AgentError::ApproveUnderTui`] first, being the more specific: a piped run that also
    /// asked to be asked per call has two things wrong with it, and only one of them is
    /// about this subcommand.
    fn drawable(&self, stdout: Device) -> Result<(), AgentError> {
        if matches!(self.run.approve, Approve::Call) {
            return Err(AgentError::ApproveUnderTui);
        }
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
        approved: &str,
        session: Option<Session>,
    ) -> Result<i32, AgentError> {
        let mut transcript = Transcript::new(&prompt, self.run.reasoning());
        transcript.note(approved);

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
            limits: TurnLimits {
                max_rounds: self.run.max_rounds(),
                ..TurnLimits::default()
            },
            observed: session
                .as_ref()
                .and_then(Session::observed)
                .map(session::request_usage),
            withheld: merged.withheld,
        };

        // Before the screen, dropped after it: the alternate screen neither redirects
        // stderr nor gives back what was written to it, so each audit record would land in
        // the pane and die with it.
        let audit = sandbx_logging::hold();

        // The screen before the keys: without raw mode ctrl-c is a signal, and the reader
        // would never see the key that is supposed to stop the turn. One lock because the
        // turn hands out two writers, `observe` and the gate's `settled`, that meet at the
        // same transcript; a `Mutex`, not a `RefCell`, so the turn's future stays `Send`.
        let pane = Mutex::new(Pane {
            screen: Screen::enter(transcript).map_err(AgentError::Screen)?,
            said: Vec::new(),
            running: Running::default(),
        });
        let mut keys = Keys::listen();
        paint(&pane, |_| {});

        let outcome = {
            let turn = run_turn(
                &mut open,
                turn,
                ctx,
                |event| paint(&pane, |transcript| transcript.event(event)),
                Gate {
                    argv: gate::ArgvGate::new(self.run.allow_tool.as_deref(), None),
                    pane: &pane,
                },
            );

            // The whole of the interrupt: the turn's future is dropped where it stood, so
            // the loop gains no stop of its own. What that costs is said below — a running
            // tool still finishes, and the process waits on it, `Runtime::drop` having no
            // timeout (#26).
            tokio::select! {
                outcome = turn => Ok(outcome),
                stopped = keys.stop() => Err(stopped),
            }
        };

        // The borrows the two seams held end with the future above. Every paint ran on this
        // task, so one that panicked would have unwound past here already.
        let mut pane = pane
            .into_inner()
            .expect("a paint that panicked unwinds past this frame");

        // Owed after the turn and never drawn: the screen is about to go, and a paint here
        // is a write that can stall on a paused terminal while the trail is still held.
        let (code, outcome, mut owed) = match outcome {
            Err(stopped) => {
                let (code, said) = match stopped {
                    Stopped::Pressed => (INCOMPLETE, interrupted()),
                    // 3 and not 2, the code a lost gate already takes: a turn nobody could
                    // see is one nobody watched, and that is not the recoverable stop an
                    // interrupt is.
                    Stopped::Gone => (NO_CONSENT, lost()),
                };
                // The call the dropped future stood on never settles, so this is the only
                // line it gets.
                let running = mem::take(&mut pane.running).stopped();
                (
                    Ok(code),
                    None,
                    [Some(said), running].into_iter().flatten().collect(),
                )
            }
            Ok(Ok(outcome)) => {
                let Ending { code, said } = ending(&outcome);
                (Ok(code), Some(outcome), said)
            }
            // No line of its own: `main` prints the error once it is returned.
            Ok(Err(error)) => (Err(AgentError::from(error)), None, Vec::new()),
        };

        // Not `?`: a store that refused the turn must still leave the transcript and the
        // trail, the answer being on the screen and nowhere else.
        let saved = match (outcome, session) {
            // `None`: no wrap-up round is sent here.
            (Some(outcome), Some(session)) => self
                .run
                .save(session, &asked, outcome, None, &merged, &mut owed),
            _ => Ok(()),
        };
        let code = saved.and(code);

        let Pane {
            mut screen, said, ..
        } = pane;
        let failed = screen.failure();
        let printed = screen.plain();
        drop(screen);

        // Released the moment there is a stderr with no screen over it, and ahead of the
        // reprint: a stdout the terminal has paused would hold the trail behind it, and a
        // signal there would lose it (#224).
        drop(audit);

        let mut stderr = io::stderr();
        let shown = Device::of(&stderr);
        given_back(
            code,
            failed,
            Remains {
                printed: &printed,
                said: &said,
                owed: &owed,
            },
            shown,
            &mut io::stdout(),
            &mut stderr,
        )
    }
}

fn interrupted() -> String {
    "sandbx: interrupted. Nothing of this turn is stored, and a tool call already running \
     finishes unseen: the process waits for it before it exits (#26)"
        .to_string()
}

/// The account of a terminal that went away mid-turn.
///
/// Its own line and not the interrupt's: the operator did not stop this turn, and telling
/// them they did is the one reading of a hangup that is certainly wrong (#264).
fn lost() -> String {
    "sandbx: the terminal went away, so the turn stopped where it stood. Nothing of it is \
     stored, and a tool call already running finishes unseen before the process exits (#26)"
        .to_string()
}

/// What a finished `tui` run has to say once the screen is gone. Not `Account`, for the
/// reason [`ending`]'s local gives.
struct Remains<'a> {
    /// The transcript as the screen drew it.
    printed: &'a str,
    /// The lines drawn during the turn, which `printed` already carries.
    said: &'a [String],
    /// The lines owed after the turn, which nothing drew.
    owed: &'a [String],
}

/// Write what the run has to say on a terminal the screen has given back, and report the
/// code.
///
/// The transcript first and always, the alternate screen having taken every row with it,
/// the answer among them. `said` again where `shown` is redirected or the reprint could not
/// be written, a failed turn owing it as much as a finished one; `owed` always, nothing
/// having drawn it. A latched draw failure is one more line and not the code: the code
/// answers what the turn did, which a failed draw is not (#257). `agent-run` does the
/// opposite with a stdout it could not write, that being the channel the answer came back
/// on. The writers are arguments so the order is a unit test.
///
/// `writeln!` and not `eprintln!`: when the screen was the terminal that hung up, both are
/// the same dead descriptor, and a panicking macro here would lose the code the turn earned
/// (#264).
fn given_back(
    code: Result<i32, AgentError>,
    failed: Option<io::Error>,
    remains: Remains<'_>,
    shown: Device,
    out: &mut impl Write,
    err: &mut impl Write,
) -> Result<i32, AgentError> {
    let reprinted = out
        .write_all(remains.printed.as_bytes())
        .and_then(|()| out.flush())
        .is_ok();

    let said = if shown == Device::Redirected || !reprinted {
        remains.said
    } else {
        &[]
    };
    for line in said.iter().chain(remains.owed) {
        let _ = writeln!(err, "{line}");
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
/// Apart from the drawing so the code is an assertion rather than a screenshot: a
/// `GateAborted` outcome holds its messages and its usage like an answered one, so nothing
/// but the code tells a caller the operator went away. A list and not a line, because two
/// bounds can cut one turn: `--max-rounds` ends the turn and `--max-tokens` ends a round
/// inside it.
fn ending(outcome: &TurnOutcome) -> Ending {
    // Not `account`: CodeQL's `rust/cleartext-logging` reads that name as a credential and
    // flags every assert that prints this list (#461). Rename back once it stops matching.
    let mut said = Vec::new();

    let code = match &outcome.stop {
        // Ahead of the bounds, as `Render::finish` has it: one turn can hit `--max-rounds`
        // and lose its operator, and only the second is unrecoverable.
        TurnStop::GateAborted => {
            said.push(
                "sandbx: the gate could no longer be asked, so the turn stopped where it \
                 was asked. That call and every call behind it were refused, and nothing \
                 further was sent"
                    .to_string(),
            );
            NO_CONSENT
        }
        TurnStop::RoundLimit { rounds } => {
            said.push(format!(
                "sandbx: out of rounds after {rounds}. No wrap-up round is sent under \
                 `tui`, so the answer ends on tool work"
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

/// The screen, and the account drawn on it.
struct Pane {
    screen: Screen,
    /// Every line drawn during the turn, in order, for a stderr the reprint does not reach.
    said: Vec<String>,
    running: Running,
}

impl Notes for Pane {
    /// Drawn, and kept: the screen takes the line with it when it goes.
    fn note(&mut self, line: &str) {
        self.screen.paint(|transcript| transcript.note(line));
        self.said.push(line.to_string());
    }
}

/// Lines owed once the turn is over: kept for stderr, never drawn.
impl Notes for Vec<String> {
    fn note(&mut self, line: &str) {
        self.push(line.to_string());
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

/// Change the transcript and redraw, or do nothing at all.
///
/// A poisoned lock is a panic already unwinding, whose terminal `Screen::drop` is about to
/// restore; panicking again here would replace that account with this one.
fn paint(pane: &Mutex<Pane>, change: impl FnOnce(&mut Transcript)) {
    if let Ok(mut pane) = pane.lock() {
        pane.screen.paint(change);
    }
}

/// The gate `tui` drives: argv decides, nothing is asked, and every call is drawn.
struct Gate<'a> {
    /// `agent-run`'s gate with no terminal, which is the whole of the decision.
    argv: gate::ArgvGate<'a, Terminal>,
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
