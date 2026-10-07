# What handing a sandboxed tool a credential would cost

A tool call that legitimately needs a secret — `bash` running `gh` — has one
option, and it is `--allow-env NAME`, which hands over the value in full. This is
why nothing better is offered, and what is offered instead. The harness's own
provider credential is `decision-credentials.md`; the mechanism that exists is
`decision-environment-allowlist.md`; what enforces any of it is
`guide-sandboxing.md`.

## The only mechanism today passes the value whole

The environment allowlist is by name. `--allow-env GH_TOKEN` reads the value out
of the harness at spawn time and puts it in the child's `environ`, where it is
readable at `/proc/<pid>/environ` by the same uid and inherited across every
`exec` the command makes. There is no redaction, no partial value and no per-tool
scoping, so the allowlist decides *whether* a secret is shared and never how much
of it.

The case that made this concrete is sandbx's own key. `agent-run` resolves
`ANTHROPIC_API_KEY` from the harness's environment, so naming that variable
handed a live provider key to a process whose arguments a model chose while
reading untrusted text.

## A placeholder needs a proxy, and the proxy is #145

The shape this project sketched first, and the one OpenShell implements: the
sandboxed process sees an opaque placeholder, and a TLS-terminating proxy
substitutes the real credential per request, only for a destination matching the
credential's scope. The secret never enters the child's memory.

Every component of it belongs to #145 — the listener the command can reach, the
interception that catches an uncooperative program, the TLS termination that makes
the allowlist about names, and the resolver that answers for those names. That
issue already owns the resolver on the grounds that it should not be built twice.
The credential half is a section of its design note, not a second mechanism.

Nor is the dependency free. No crate depends on a server-side HTTP stack; hyper
arrives only through `wiremock`, a dev-dependency, and `tokio`'s `net` feature is
enabled nowhere. A new network-facing service with a new trust boundary is a large
thing to add to a project whose claim is that the boundaries are kernel ones.

## Interception is cooperation, and sandbx ships the binary that defeats it

`HTTP_PROXY` binds only programs that read it, and only for HTTP. A transparent
redirect needs `nftables` rules inside a network namespace, which needs
privileges sandbx does not hold. An `LD_PRELOAD` shim on `connect` is stepped
around by a static binary and by a direct syscall — and the release artifacts are
static musl, so the project's own binaries defeat its own interception.

Write the claim out and the verdict is in the sentence:

> sandbx replaces a credential with a placeholder and resolves the real value only
> for requests whose destination matches its scope — provided the program honours
> `HTTP_PROXY`, is not statically linked and does not `connect` directly; and
> provided you install the CA sandbx generates, after which sandbx reads every
> byte the tool sends.

A claim that cannot be written plainly is the signal the mechanism is not one.

## Termination would widen the boundary it is meant to narrow

Resolving a credential per request means reading the request, which means
terminating TLS, which means the sandboxed command trusts a CA sandbx controls.
Two things follow, both in the wrong direction. The command can be
man-in-the-middled for every destination, not only the credential's. And the
harness reads plaintext it previously could not — bodies a tool sent to a service
that has nothing to do with the secret.

Against the threat this exists for, a model choosing a tool call's arguments from
untrusted text, that is a larger exposure than passing the variable.

## A broker needs a channel the sandbox does not have

The other shape: the credentialed operation runs in the harness, which holds the
secret, and the child asks for it over a channel. Enforcement would be positional
— no step moves the secret — which is weaker than a kernel refusal but honest.

There is no channel. A descriptor of its own was tried and rejected for the audit
log; `decision-helper-audit-channel.md` has the finding, and it is the same here:
`unsafe_code` is forbidden workspace-wide, safe adoption child-side needs
`OwnedFd::from_raw_fd` or `BorrowedFd::borrow_raw`, and the only descriptors `std`
hands a child without `unsafe` are 0, 1 and 2. The kernel half works; the safe
adoption does not exist. The remaining options each buy the secret's privacy with
a wider sandbox:

| Channel | What granting it costs |
|---|---|
| loopback TCP | `--allow-network <port>` drops `CLONE_NEWNET`, so the command runs in the host netns and reaches that port on every routable host, host loopback included |
| unix socket | `--allow-unix-sockets` is all-or-nothing: every pathname socket the filesystem policy can reach, the ssh-agent and the docker socket among them |
| stdin/stdout | already spent on the command's own I/O, which `bash` exists to relay |

"sandbx keeps the credential out of the tool's memory by granting the tool a
network it did not previously have" refutes itself.

A built-in whose body performs the operation in-harness needs no channel, the
tool-call protocol being one already. It is not ruled out here — it is #186, where
it joins the question #165 and #169 are already asking about who sees a call and
when, because an authenticated call is the case where per-call consent matters
most and approve-once-per-run is least defensible.

## What is left is a refusal, and it is one

`agent-run` refuses `--allow-env ANTHROPIC_API_KEY`. The claim, plainly:

> sandbx makes the provider call in-process, so no tool call needs that value, and
> `agent-run` will not pass it. Every other variable you name is still passed in
> full.

Enforcement is positional and complete: the value does not reach the child because
no step puts it there. The refusal is decided from argv before a policy is
derived, before a key is read, and before a request goes out, so it needs no
channel, no proxy, no dependency and no field on `SandboxPolicy`.

It is worth being exact about how much this buys. The flags are the operator's — a
hijacked turn cannot pass `--allow-env`. What it removes is operator error:
exporting the key for `agent-run` to spend and then naming it because a tool asked
for a credential, or carrying a `sandbox-run` recipe across to `agent-run`.

## Refused in `agent-run`, passed by `sandbox-run`

Under `sandbox-run` the operator named the program and typed its arguments.
`--allow-env ANTHROPIC_API_KEY -- ./my-llm-script` is a legitimate invocation: the
child *is* the thing calling the provider. Refusing there would override an
operator about a program sandbx did not choose, on the subcommand that exists to
be the honest escape hatch.

Under `agent-run` the child never calls the provider and the arguments are
model-chosen, so there is no invocation where the flag is the right answer and a
refusal forecloses nothing.

The rule that keeps the asymmetry from becoming two policies: **the two
subcommands may differ by a refusal, never by a policy.** `agent-run` may return
`Err` where `sandbox-run` returns `Ok`; it may never return a quietly narrower
`Ok`. `the_policy_matches_what_sandbox_run_derives` asserts the second half across
every axis, and `a_divergence_between_the_run_subcommands_is_a_refusal` pins the
first — the one shape a difference is allowed to take.

Which makes the rule a test to apply to the next route, and the test is
**decidable from argv**. `--allow-env ANTHROPIC_API_KEY` is a name matched against
a constant, so `agent-run` can refuse it with nothing derived. A route reachable
only by asking whether a *granted path contains* one the harness owns is not: the
answer needs the derived policy, which makes a one-sided answer a policy
difference rather than a refusal, and the rule forbids it — so it must be refused
on both subcommands or on neither. That is why the config-directory route (#184)
and the procfs one (#192) are not simply more of this, and why neither is
subtractable either: Landlock composes rules by union with no exclusion form, as
`decision-default-policy.md` records in rejecting a carve-out for the enforcer
binary. The question both leave open is the same one — what the harness does when
a grant it was given contains something the harness itself owns — and it is not
answered here.

## By name, and without asking the environment

The refusal does not check whether the variable is set, and the first reason is
the hard one: a refusal conditioned on the live environment could not be tested
here at all. `set_var` is `unsafe fn` under edition 2024 and `unsafe_code` is
forbidden even in test binaries, which is why `resolve_api_key` takes an injected
lookup. A condition no test can reach is a condition that rots.

Second, a flag is a statement of intent, and the intent is refusable whether this
shell exports the key this minute. Third, it makes the answer deterministic: the
same argv gets the same verdict on every host, so the message an operator reports
is the message anybody can reproduce.

## One name the harness owns, not a pattern

A denylist over `*_KEY`, `*_TOKEN`, `*_SECRET` is a *prediction* about naming, and
`decision-environment-allowlist.md` rejected exactly that shape: wrong on arrival,
and silently stops covering the case the first time a non-matching name appears.

This is an *identity*. The refused name is read from `auth::ENV_VAR`, the same
constant `env_key` dereferences and `auth status` reports on, so it moves with the
constant rather than drifting away from it — including when a second provider
adapter (#59) brings a second one. And the directions are opposite: a denylist
tries to catch secrets it does not know about, while this catches the one secret it
does, and claims nothing about any other name.

`the_credential_refusal_matches_one_exact_name` is where that claim is falsifiable:
`GH_TOKEN`, `ANTHROPIC_API_KEY_OLD`, `MY_ANTHROPIC_API_KEY`, `anthropic_api_key`
and `ANTHROPIC_API_KE` all still derive a policy.

## What the refusal does not close

The `--allow-env` route, which is narrower than "the environment" and has to be
said that way round. Two others reach the same key and neither is a flag the
refusal reads:

- A key written by `sandbx auth login` lives under the config home, so a read
  grant covering it hands the file to a tool — #184. `SECURITY.md` has disclosed
  that route in prose since before the refusal existed; closing it is a separate
  enforcement step with the same shape as #173's session root.
- A key the operator *exported* is in the harness's environment, and the harness
  is not sandboxed while procfs is the host's, so a filesystem grant reaching
  `/proc` reaches `/proc/<harness-pid>/environ` — #192. This is not specific to a
  credential — it is the reason `SECURITY.md` says not to grant `/proc` at all —
  but a reader who takes the refusal as "the environment is handled" has the wrong
  conclusion, so the bullet says both.

And handing a tool a credential it legitimately needs is still unanswered. Nothing
above is a mechanism for it. `gh` in `bash` with a real token has exactly one
spelling, and it is `--allow-env` with the value in full.

## What must not happen in the meantime

**No credential value may enter `SandboxPolicy`, and no placeholder may be
recorded before something resolves it.** A policy that carries a value carries it
in argv, the one place a sandboxed command is guaranteed to be able to read it;
that is why the flag is `--allow-env NAME` and not `NAME=VALUE`. A policy carrying
a *placeholder* nothing yet resolves is worse than one carrying a value, because
the next reader of the type assumes a resolution step exists. The axis carries
names, and the single value it imposes is a compile-time constant the child could
read out of the binary it is about to `exec` anyway. A per-run placeholder would
need a new values path through `HelperArgs` encode/decode and the helper's
inherited-environment check — so a placeholder may travel that way and nothing
real ever can. If an intermediate step is wanted it is a separate opt-in type the
enforcement path rejects outright, not a value-bearing field on the existing one.

The same rule covers the refusal. The one name refused is the one the harness
dereferences itself, and no second name joins it until something other than a
naming convention identifies it as a credential.

## What was rejected

**A value-bearing environment axis** — `--allow-env NAME=VALUE`, so the harness
need not hold the secret. It moves the credential out of the harness while leaving
it fully exposed to the child, which is the half that matters, and the value would
cross as argv besides. The flag's shape is the decision, and
`decision-environment-allowlist.md` is where it was made.

**A refusal by pattern.** Covered above: a prediction about naming, in a project
whose allowlist exists because that prediction fails.

**A warning instead of a refusal.** `--allow-env ANTHROPIC_API_KEY` printing "this
exposes your key" and continuing is a fail-open shape — the same one
`decision-credentials.md` rejects for "keyring, else file". The operator who passed
the flag by mistake is the operator who will not read the line, and the one who
meant it has `sandbox-run`.

**Stripping the variable instead of refusing it.** Silently dropping the name
derives a quietly narrower policy from the same flags, which is exactly the
divergence `the_policy_matches_what_sandbox_run_derives` exists to catch, and the
symptom is a tool failing to authenticate with nothing connecting it to a flag that
appeared to be accepted.

**Refusing in `Grants` for both subcommands.** It would read as the simpler
placement — one check, no asymmetry — but it breaks a legitimate `sandbox-run`
invocation, and the refusal belongs where the reason for it is. `Grants` does not
know which subcommand is asking, and should not have to.

## What it costs

Nothing a tool could do before stops working, and no generality was bought either.
The refusal removes one flag from one subcommand, and that flag had no legitimate
use there. What it does not do is answer the question in the title: a brokered
capability needs a channel that does not exist, and a placeholder needs #145.

The honest summary is that #41 ends in a decision rather than a mechanism, and in
one refusal that is enforceable today.

## The mutation check

Delete the `HarnessCredential` check in `AgentRun::policy`:

```
delete the if in AgentRun::policy
   ──► agent_run_refuses_the_harness_credential               fails
       a_divergence_between_the_run_subcommands_is_a_refusal  fails
       the_refusal_lands_before_the_policy_is_derived         fails
       an_exported_credential_is_refused_too                  fails
       the_credential_refusal_outranks_the_home_…             fails
       the_credential_refusal_matches_one_exact_name          passes  ◄── derives nothing
       sandbox_run_still_passes_the_harness_credential        passes  ◄── the other subcommand
       the_refused_variable_is_spelled_out                    passes  ◄── a constant, not a rule
       the_policy_matches_what_sandbox_run_derives            passes  ◄── the surprise
```

The last line is why `a_divergence_…` has to exist. The invariant test the
asymmetry is in tension with — the one asserting the two subcommands derive the
same policy from the same flags — does not notice the refusal going away, because
a refusal is not a policy and that test only compares policies.

Run rather than predicted: the five failures are the five above, and cargo stops
at the first failing binary, so the two spawned cases have to be run with
`--test cwd_policy` to be seen at all.
