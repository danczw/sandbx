//! `sandbx tui`: one prompt, one turn, drawn on a screen a keypress can stop.
//!
//! Every flag, the policy and the session are `agent-run`'s; what differs is where the
//! turn is reported and that an operator can end one mid-flight. `--approve call` is
//! refused rather than downgraded (#225), and the per-call account is drawn on the screen
//! instead of written to stderr, which the alternate screen does not redirect (#224).

use std::io::IsTerminal;
use std::sync::{Mutex, PoisonError};

use sandbx_agent::{
    ApprovalDecision, CallGate, Settled, ToolCall, Turn, TurnLimits, TurnOutcome, TurnStop,
    run_turn,
};
use sandbx_providers::{
    AnthropicClient, ContentBlock, EventStream, Prompt, ProviderError, RequestMessage, Role,
    StopReason, Thinking,
};
use sandbx_session::Session;
use sandbx_tools::{BuiltinTool, ExecutionContext};
use sandbx_tui::{Hint, Keys, Screen, Transcript};

use super::{AgentRun, Approve, INCOMPLETE, NO_CONSENT, Terminal, gate, orientation};
use crate::AgentError;
use crate::{logging, session};

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
    /// `0` for an answer the model finished, `2` for one that `--max-rounds` ended or that
    /// the operator interrupted — in both cases the screen says which.
    ///
    /// # Errors
    ///
    /// [`AgentError::NotATerminal`] and [`AgentError::ApproveUnderTui`] land before
    /// anything else, including before the credential is read. The rest are
    /// [`AgentRun::execute`]'s, plus [`AgentError::Screen`] for a terminal that stopped
    /// taking what was drawn on it.
    pub async fn execute(&self) -> Result<i32, AgentError> {
        let prompt = self.run.prompt();
        if prompt.trim().is_empty() {
            return Err(AgentError::EmptyPrompt);
        }

        // Before the policy: neither refusal needs one, and a run that cannot be drawn
        // must not read a credential on the way to finding that out.
        self.drawable(std::io::stdout().is_terminal())?;

        let policy = self.run.policy()?;
        let system =
            orientation::system_prompt(&policy, self.run.allow_tool.as_deref(), self.run.system());
        let ctx = ExecutionContext::new(policy);

        let approved = gate::approved_tools(self.run.allow_tool.as_deref()).join(", ");
        // On stderr as well as on the screen: the screen is gone the moment the process
        // ends, and this is the line a redirected log needs most (#224).
        eprintln!("sandbx: tools approved: {approved}");

        let client = AnthropicClient::new(crate::auth::api_key()?)?;
        let session = session::open(self.run.session())?;

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
    /// [`AgentError::ApproveUnderTui`] first, decidable from argv alone and the more
    /// specific of the two: a piped run that also asked to be asked per call has two
    /// things wrong with it, and only one of them is about this subcommand.
    fn drawable(&self, terminal: bool) -> Result<(), AgentError> {
        if matches!(self.run.approve, Approve::Call) {
            return Err(AgentError::ApproveUnderTui);
        }
        if !terminal {
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
        let mut transcript = Transcript::new(&prompt, self.run.show_thinking);
        transcript.note(&format!("sandbx: tools approved: {approved}"));

        let asked = RequestMessage {
            role: Role::User,
            content: vec![ContentBlock::Text { text: prompt }],
        };

        let mut history = match &session {
            Some(session) => session::request_history(session.messages()),
            None => Vec::new(),
        };
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

        // Before the screen, dropped after it: `sandbx-core` emits the audit trail on
        // stderr for every guarded access, and the alternate screen neither redirects it
        // nor gives it back, so each record would land in the pane and die with it.
        let audit = logging::hold();

        // The screen before the keys: without raw mode ctrl-c is a signal, and the reader
        // would never see the key that is supposed to stop the turn.
        let screen = Screen::enter().map_err(AgentError::Screen)?;
        let mut keys = Keys::listen();

        let pane = Mutex::new(Pane { transcript, screen });
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
                outcome = turn => Some(outcome),
                () = keys.stop() => None,
            }
        };

        // The borrows the two seams held end with the future above.
        let mut pane = pane.into_inner().unwrap_or_else(PoisonError::into_inner);

        let (code, outcome, account) = match outcome {
            None => (
                Ok(INCOMPLETE),
                None,
                vec![
                    "sandbx: interrupted. Nothing of this turn is stored, a tool call \
                     already running finishes unseen, and the process waits for it \
                     before it exits (#26)"
                        .to_string(),
                ],
            ),
            Some(Ok(outcome)) => {
                let (code, account) = ending(&outcome);
                (Ok(code), Some(outcome), account)
            }
            Some(Err(error)) => {
                // Drawn before it is returned: the screen is about to be torn down, and
                // the operator reads the reason there rather than in what scrolls past
                // after.
                let line = format!("sandbx: {error}");
                (Err(AgentError::from(error)), None, vec![line])
            }
        };

        for line in &account {
            pane.transcript.note(line);
        }

        // Before the key, not after: the hold ends on an operator who may not come back,
        // and a hangup there would lose a finished turn that was already paid for.
        if let Some(outcome) = outcome
            && let Some(session) = session
        {
            self.run.save(session, &asked, outcome, &merged)?;
        }

        // Held until a key, then put back: the alternate screen takes the transcript with
        // it, and a turn whose last rounds nobody read was not watched. Every cell and not
        // the changed ones, because `save` writes to a stderr the screen does not redirect
        // and ratatui would otherwise leave that line where it landed.
        pane.redraw(Hint::Done);
        keys.press().await;
        let failed = pane.screen.failure();
        drop(pane);

        // Only now is there a stderr with no screen over it: the trail first, as it was
        // emitted during the turn, then the account. The account is written again here
        // because the pane went with the screen, and the line saying why a run exited 3
        // rather than 2 is the one a redirected log needs most (#224). Not on the error
        // path, where `main` reports the same error itself.
        drop(audit);
        if code.is_ok() {
            for line in &account {
                eprintln!("{line}");
            }
        }

        let code = code?;
        match failed {
            Some(error) => Err(AgentError::Screen(error)),
            None => Ok(code),
        }
    }
}

/// The code a finished turn exits with, and every line accounting for it.
///
/// Apart from the drawing so the code is an assertion rather than a screenshot: a
/// `GateAborted` outcome holds its messages and its usage like an answered one, so nothing
/// but the code tells a caller the operator went away.
///
/// Two bounds can cut one turn, so the account is a list: `--max-rounds` ends the turn and
/// `--max-tokens` ends a round inside it, and a turn that met both has to say both.
fn ending(outcome: &TurnOutcome) -> (i32, Vec<String>) {
    let mut account = Vec::new();

    let code = match &outcome.stop {
        // Ahead of the bounds, as `render.rs:219` has it: a turn can hit `--max-rounds` and
        // lose its operator in the same round, and the operator is the one a caller cannot
        // find out about any other way.
        TurnStop::GateAborted => {
            account.push(
                "sandbx: the gate could no longer be asked, so the turn stopped where it \
                 was asked. That call and every call behind it were refused, and nothing \
                 further was sent"
                    .to_string(),
            );
            NO_CONSENT
        }
        TurnStop::RoundLimit { rounds } => {
            account.push(format!(
                "sandbx: out of rounds after {rounds}. No wrap-up round is sent under \
                 `tui`, so the answer ends on tool work"
            ));
            INCOMPLETE
        }
        // Not matched exhaustively: a stop this does not know about is an answer it has no
        // account of. One that documents an exit code of its own needs an arm above
        // instead, or `tui` contradicts a code `agent-run` already claims.
        _ => 0,
    };

    // The outcome's own figure, not the stream's, and read whatever the stop was: the
    // round that carried the reply can be cut at `--max-tokens` by itself, which is an
    // answer that stops mid-sentence and must not exit 0.
    if outcome.round_stop == Some(StopReason::MaxTokens) {
        account.push(
            "sandbx: the answer stops at `--max-tokens`, mid-sentence and not at the \
             model's own end of turn"
                .to_string(),
        );

        // Never over a code already chosen: a turn can lose its operator and be cut in the
        // same round, and the cut is the recoverable one.
        return (if code == 0 { INCOMPLETE } else { code }, account);
    }

    (code, account)
}

/// The transcript and the screen it is drawn on.
///
/// One lock around both because the turn hands out two writers — `observe` and the gate's
/// `settled` — and they have to meet at the same transcript. A `Mutex` and not a `RefCell`
/// so the turn's future stays `Send`.
struct Pane {
    transcript: Transcript,
    screen: Screen,
}

impl Pane {
    fn repaint(&mut self, hint: Hint) {
        self.screen.draw(&self.transcript, hint);
    }

    fn redraw(&mut self, hint: Hint) {
        self.screen.redraw(&self.transcript, hint);
    }
}

/// Change the transcript and redraw, or do nothing at all.
///
/// A poisoned lock is a panic already unwinding, whose terminal `Screen::drop` is about to
/// restore; panicking again here would replace that account with this one.
fn paint(pane: &Mutex<Pane>, change: impl FnOnce(&mut Transcript)) {
    if let Ok(mut pane) = pane.lock() {
        change(&mut pane.transcript);
        pane.repaint(Hint::Running);
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
        self.argv.approve(call)
    }

    /// The same line `agent-run` writes, drawn instead of printed.
    ///
    /// `ArgvGate::settled` puts it on stderr, which the alternate screen does not redirect:
    /// the line would paint over the pane and be lost with it.
    fn settled(&mut self, call: Settled<'_>) {
        let line = gate::line(call);
        paint(self.pane, |transcript| transcript.call(&line));
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::{Cli, Command};

    /// The `tui` invocation `argv` describes, as clap parses it.
    fn tui(argv: &[&str]) -> Tui {
        let cli = Cli::try_parse_from(argv).expect("argv parses");
        match cli.command {
            Command::Tui(tui) => tui,
            other => panic!("not a tui invocation: {other:?}"),
        }
    }

    /// Drawn over a pipe, the pane would land in whatever read it as escape sequences —
    /// and the operator would have no screen to interrupt from.
    #[test]
    fn a_stdout_that_is_not_a_terminal_is_refused() {
        let tui = tui(&["sandbx", "tui", "--", "what is here?"]);

        // Non-vacuous: the same invocation with a terminal is allowed, so the refusal
        // below is the pipe and not something else about the flags.
        assert!(tui.drawable(true).is_ok());
        assert!(matches!(tui.drawable(false), Err(AgentError::NotATerminal)));
    }

    /// Refused and not downgraded to the argv answer: a flag that asks for a narrower
    /// regime must not be served the wider one it asked to replace (#225).
    #[test]
    fn approve_call_is_refused_whether_or_not_there_is_a_terminal() {
        let tui = tui(&[
            "sandbx",
            "tui",
            "--approve",
            "call",
            "--allow-tool",
            "bash",
            "--",
            "what is here?",
        ]);

        for terminal in [false, true] {
            assert!(
                matches!(tui.drawable(terminal), Err(AgentError::ApproveUnderTui)),
                "terminal={terminal}"
            );
        }
    }

    /// A turn that stopped `stop`, whose last round stopped `round_stop`.
    fn outcome(stop: TurnStop, round_stop: Option<StopReason>) -> TurnOutcome {
        TurnOutcome {
            messages: Vec::new(),
            usage: None,
            withheld: 0,
            stop,
            round_stop,
        }
    }

    /// A lost operator outranks a cut round, and both outrank an answer.
    ///
    /// Asserting the code and not the note: `GateAborted` keeps the turn's messages and
    /// usage, so an outcome that lost its operator is as well formed as one that answered
    /// — the code is the only thing that tells them apart, and `agent-run` already exits 3
    /// for it in a shipped claim (#218).
    #[test]
    fn a_gate_that_could_not_be_asked_exits_three_and_a_cut_round_two() {
        let code = |stop| ending(&outcome(stop, None)).0;

        assert_eq!(code(TurnStop::GateAborted), NO_CONSENT);
        assert_eq!(code(TurnStop::RoundLimit { rounds: 4 }), INCOMPLETE);

        // Non-vacuous in the other direction: a finished answer takes the `_` arm and
        // exits 0, so the two codes above are the stops and not the function.
        assert_eq!(ending(&outcome(TurnStop::Answered, None)), (0, Vec::new()));
    }

    /// The bound `TurnStop` does not carry: a round cut at `--max-tokens` ends the answer
    /// mid-sentence and still stops as `Answered`, so reading the stop alone would exit 0
    /// on a truncated reply — and the exit table this branch widened to `tui` says 2.
    #[test]
    fn an_answer_cut_at_max_tokens_exits_two_whatever_the_stop_was() {
        let cut = || Some(StopReason::MaxTokens);

        assert_eq!(ending(&outcome(TurnStop::Answered, cut())).0, INCOMPLETE);
        assert_eq!(
            ending(&outcome(TurnStop::RoundLimit { rounds: 4 }, cut())).0,
            INCOMPLETE
        );

        // The cut does not lower a code already chosen, and it adds its own line to a turn
        // that met both bounds.
        let (code, account) = ending(&outcome(TurnStop::GateAborted, cut()));
        assert_eq!(code, NO_CONSENT);
        assert_eq!(account.len(), 2, "{account:?}");

        // Non-vacuous: the same stop with a round that was not cut exits 0, so the code
        // above is the cut and not the fixture.
        assert_eq!(
            ending(&outcome(TurnStop::Answered, Some(StopReason::EndTurn))).0,
            0
        );
    }

    /// Every code the screen reports comes with the line that explains it: a bare 3 in a
    /// shell is not an account of where the turn stopped.
    #[test]
    fn a_stop_that_is_not_an_answer_says_why() {
        let stops = [
            outcome(TurnStop::GateAborted, None),
            outcome(TurnStop::RoundLimit { rounds: 4 }, None),
            outcome(TurnStop::Answered, Some(StopReason::MaxTokens)),
        ];

        for stop in &stops {
            let (code, account) = ending(stop);
            assert_ne!(code, 0, "{stop:?}");
            assert!(
                account.iter().all(|line| line.starts_with("sandbx: ")),
                "{account:?}"
            );
        }
    }

    /// The flattened flags are the same flags: one `--allow-tool` cannot approve two
    /// different sets depending on which subcommand read it.
    #[test]
    fn the_approved_tools_are_what_the_same_flags_approve_under_agent_run() {
        let flags = ["--allow-tool", "write"];
        let prompt = ["--", "what is here?"];

        let tui = tui(&[&["sandbx", "tui"], &flags[..], &prompt[..]].concat());
        let Command::AgentRun(run) =
            Cli::try_parse_from([&["sandbx", "agent-run"], &flags[..], &prompt[..]].concat())
                .expect("argv parses")
                .command
        else {
            panic!("not an agent-run invocation");
        };

        let approved = gate::approved_tools(tui.run.allow_tool.as_deref());
        assert_eq!(approved, gate::approved_tools(run.allow_tool.as_deref()));
        assert!(approved.contains(&"write"), "{approved:?}");
        assert!(!approved.contains(&"bash"), "{approved:?}");
    }
}
