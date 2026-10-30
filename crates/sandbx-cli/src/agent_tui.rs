//! `sandbx tui`: one prompt, one turn, drawn on a screen a keypress can stop.
//!
//! Every flag, the policy and the session are `agent-run`'s; what differs is where the
//! turn is reported and that an operator can end one mid-flight. `--approve call` is
//! refused rather than downgraded (#225), and the per-call account is drawn on the screen
//! instead of written to stderr, which the alternate screen does not redirect (#224).

use std::io::{self, Write};
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

        let approved = gate::approved_tools(self.run.allow_tool.as_deref()).join(", ");
        // On stderr as well as on the screen: the screen is gone the moment the process
        // ends, and this is the line a redirected log needs most (#224).
        eprintln!("sandbx: tools approved: {approved}");

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
        transcript.note(&format!("sandbx: tools approved: {approved}"));

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
        let pane = Mutex::new(Screen::enter(transcript).map_err(AgentError::Screen)?);
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
            // the loop gains no stop of its own. What that costs is drawn below.
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

        let (code, outcome, account) = match outcome {
            Err(Stopped::Pressed) => (
                Ok(INCOMPLETE),
                None,
                vec![
                    "sandbx: interrupted. Nothing of this turn is stored, a tool call \
                     already running finishes unseen, and any key leaves — after which \
                     the process waits for that call before it exits (#26)"
                        .to_string(),
                ],
            ),
            // 3 and not 2, the code a lost gate already takes: a turn nobody could see is
            // one nobody watched, and that is not the recoverable stop an interrupt is.
            Err(Stopped::Gone) => (Ok(NO_CONSENT), None, vec![lost()]),
            Ok(Ok(outcome)) => {
                let (code, account) = ending(&outcome);
                (Ok(code), Some(outcome), account)
            }
            Ok(Err(error)) => {
                // Drawn before it is returned: the operator reads the reason on the screen
                // rather than in what scrolls past after it is torn down.
                let line = format!("sandbx: {error}");
                (Err(AgentError::from(error)), None, vec![line])
            }
        };

        // Before the key, not after: the hold ends on an operator who may not come back,
        // and a hangup there would lose a finished turn that was already paid for.
        if let Some(outcome) = outcome
            && let Some(session) = session
        {
            self.run.save(session, &asked, outcome, &merged)?;
        }

        // Held until a key: the alternate screen takes the transcript with it, and a turn
        // whose last rounds nobody read was not watched. Every cell and not the changed
        // ones, because `save` writes to a stderr the screen does not redirect. What the
        // wait costs the held trail is #224.
        pane.finish(|transcript| {
            for line in &account {
                transcript.note(line);
            }
        });
        keys.press().await;
        let failed = pane.failure();
        drop(pane);

        // Only now is there a stderr with no screen over it, which is why the trail is
        // dropped here: in emission order, ahead of everything `reported` writes.
        drop(audit);

        reported(code, failed, &account)
    }
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

/// Write what the run has to say on a stderr with no screen over it, and report the code.
///
/// The account again, the pane having gone with the screen and a redirected log needing the
/// line that says why a run exited 3 rather than 2 (#224). A latched draw failure is one
/// more line and not the code — `context/guide-tui.md` has why, and why `agent-run` does the
/// opposite. Apart from `execute` so the precedence is a unit test: `Screen` needs a
/// terminal no test has, and the latch is private with no setter.
///
/// `writeln!` and not `eprintln!`: when the screen was the terminal that hung up, stderr is
/// the same dead descriptor, and a panicking macro here would lose the code the turn earned
/// (#264).
fn reported(
    code: Result<i32, AgentError>,
    failed: Option<io::Error>,
    account: &[String],
) -> Result<i32, AgentError> {
    // First, so a turn that failed outright prints neither: its own error is the account.
    let code = code?;
    let mut stderr = io::stderr();

    for line in account {
        let _ = writeln!(stderr, "{line}");
    }
    // Through the variant's own `Display`, so the wording is the one `main` would have
    // printed had this stayed the return value.
    if let Some(error) = failed {
        let _ = writeln!(stderr, "sandbx: {}", AgentError::Screen(error));
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
fn ending(outcome: &TurnOutcome) -> (i32, Vec<String>) {
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
        return (if code == 0 { INCOMPLETE } else { code }, said);
    }

    (code, said)
}

/// Change the transcript and redraw, or do nothing at all.
///
/// A poisoned lock is a panic already unwinding, whose terminal `Screen::drop` is about to
/// restore; panicking again here would replace that account with this one.
fn paint(pane: &Mutex<Screen>, change: impl FnOnce(&mut Transcript)) {
    if let Ok(mut pane) = pane.lock() {
        pane.paint(change);
    }
}

/// The gate `tui` drives: argv decides, nothing is asked, and every call is drawn.
struct Gate<'a> {
    /// `agent-run`'s gate with no terminal, which is the whole of the decision.
    argv: gate::ArgvGate<'a, Terminal>,
    pane: &'a Mutex<Screen>,
}

impl CallGate for Gate<'_> {
    /// Delegated, never re-derived: one `--allow-tool` approving two different sets across
    /// two subcommands is the divergence nobody notices until a `bash` runs.
    fn approve(&mut self, call: ToolCall<'_>) -> ApprovalDecision {
        self.argv.approve(call)
    }

    /// The same line `agent-run` writes, drawn instead of printed: `ArgvGate::settled` puts
    /// it on stderr, which the alternate screen neither redirects nor gives back.
    fn settled(&mut self, call: Settled<'_>) {
        let line = gate::line(call);
        paint(self.pane, |transcript| transcript.note(&line));
    }
}

#[cfg(test)]
#[path = "agent_tui_tests.rs"]
mod tests;
