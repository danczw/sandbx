//! `--approve call` under `tui`: the question asked on the screen that took the terminal.
//!
//! What is asked, and what an answer means, are `agent_prompt.rs`'s; this is only where the
//! question is drawn and the answer comes from. A gate cannot await, so it waits on the key
//! thread `sandbx-tui-input` owns, which no task of the runtime feeds — the class
//! `context/decision-approval-gate.md` allows a gate to block on.

use sandbx_approval::{ApprovalDecision, ToolCall};
use sandbx_tui_input::{Answers, Reply};

use super::prompt::{
    CLOSED, Consent, INTERRUPTED, Notes, Operator, REFUSED, UNCLEARED, UNDRAWN, abort, deny,
    question,
};

/// The keys that answer. Lowercase and bare, `Y` and ctrl-y being neither: a modified key
/// is a shortcut and a capital is a held shift, and neither is a deliberate yes.
const ANSWERS: &[char] = &['y', 'n', 'a'];

/// Where the question is put on the screen, and so where the account of each call goes:
/// asked and told on one channel, or an operator answers call N+1 blind to call N.
pub(super) trait Shows: Notes {
    /// Draw `lines` as the question, replacing any showing, and say whether they reached
    /// the screen. False is a screen that has failed, or one that cannot be reached.
    fn show(&mut self, lines: &[&str]) -> bool;

    fn clear(&mut self);
}

/// Where the answer comes from, as a trait so a test can script it.
pub(super) trait Replies {
    /// Open the question to answers; see [`Answers::arm`].
    fn arm(&self, accepts: &'static [char]) -> nix::Result<()>;

    /// Block until the operator answers or can no longer be asked.
    fn wait(&self) -> Reply;

    /// What the operator has already done to end the turn, if anything.
    fn stopped(&self) -> Option<Reply>;
}

impl Replies for Answers {
    fn arm(&self, accepts: &'static [char]) -> nix::Result<()> {
        Answers::arm(self, accepts)
    }

    fn wait(&self) -> Reply {
        Answers::wait(self)
    }

    fn stopped(&self) -> Option<Reply> {
        Answers::stopped(self)
    }
}

/// The operator, as `tui` reaches them: asked on the screen, answered on the keys.
pub(super) struct Modal<S, R> {
    screen: S,
    replies: R,
    consent: Consent,
}

impl<S, R> Modal<S, R> {
    pub(super) fn new(screen: S, replies: R) -> Self {
        Self {
            screen,
            replies,
            consent: Consent::new(),
        }
    }
}

impl<S: Shows, R: Replies> Operator for Modal<S, R> {
    fn ask(&mut self, call: ToolCall<'_>) -> ApprovalDecision {
        // Before the `a` that covers a tool: that was the operator's word about the tool,
        // not a way past a stop they gave since, or a terminal that has gone. A covered
        // call would otherwise run, and a running call cannot be cancelled (#26).
        match self.replies.stopped() {
            Some(Reply::Interrupted) => return deny(INTERRUPTED),
            Some(Reply::Closed) => return abort(CLOSED),
            Some(Reply::Key(_)) | None => {}
        }
        if self.consent.covers(call.tool) {
            return ApprovalDecision::Allow;
        }

        let [head, tail] = question(call);
        // Not asked over a question nobody saw: a key pressed meanwhile would answer it.
        if !self.screen.show(&[&head, &tail]) {
            self.screen.clear();
            return abort(UNDRAWN);
        }

        // After the draw and never before: a key pressed while nothing was on screen to
        // answer must not be taken for an answer to it, and `arm` is what forgets those.
        let reply = match self.replies.arm(ANSWERS) {
            Ok(()) => self.replies.wait(),
            Err(_) => {
                self.screen.clear();
                // Refused rather than asked anyway: the queue may already hold its answer.
                return abort(UNCLEARED);
            }
        };
        self.screen.clear();

        match reply {
            Reply::Key(key) => {
                let mut typed = [0; 4];
                // `None` is unreachable, `arm` keeping only the three; a key that was not
                // one of them is not consent.
                self.consent
                    .answer(call.tool, key.encode_utf8(&mut typed))
                    .unwrap_or_else(|| deny(REFUSED))
            }
            Reply::Interrupted => deny(INTERRUPTED),
            Reply::Closed => abort(CLOSED),
        }
    }

    fn report(&mut self, line: &str) {
        self.screen.note(line);
    }
}

#[cfg(test)]
#[path = "tui_modal_tests.rs"]
mod tests;
