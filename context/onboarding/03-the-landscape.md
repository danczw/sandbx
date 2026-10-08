# Every harness chooses where the boundary goes

This chapter looks at the whole of View 1 in
[04 — the architecture](04-the-architecture.md) — the three processes, and which
of them are unconfined — from the outside, beside the equivalent picture in
other projects. It exists so that chapter 01's thesis reads as one position in a
field rather than as the only way to build the thing. What follows is a snapshot
of October 2026; every project here moves, and several of these pages changed
during the week this was written.

Two rules govern it, and they are worth stating before the first table.

- **Every claim about another project comes from that project's own
  documentation,** linked at the end. Where their docs do not answer an axis,
  the cell says their docs do not say, rather than filling the gap from a blog
  post, a release note or a reading of their source.
- **There are no security claims about anyone else here.** The axes record
  *where* each project puts a boundary and what it does with nothing configured.
  Those are design facts. How well any of them holds is not this chapter's
  question and not this project's standing to answer. Where a quoted sentence
  does evaluate something, it is that project evaluating its own work, and it is
  marked as theirs.

## Four axes, and why these four

A feature list compares the wrong thing. Two harnesses can both say "sandboxed
shell commands" and mean a userspace syscall interposer and a process-level
LSM, which fail differently and under different assumptions. So the comparison
runs on four questions that each have a mechanical answer.

| axis | the question | why it separates things |
|---|---|---|
| where the boundary is | process, container, virtual machine, or none | it fixes what has to be compromised to get out, and what the project depends on to hold |
| who decides a tool call | a human each time, a static rule, or a model | a rule can be audited before the run; a model's verdict cannot |
| the default with nothing configured | what a first run on a fresh machine permits | almost every real session is the default, and a default is a design statement |
| whether the harness confines itself | only the commands, or the harness too | the harness is the process that parses untrusted input, so this is the axis that is usually answered "only the commands" |

The fourth axis is the one that gets skipped, and it is the sharpest. A harness
that confines only what it spawns has drawn a boundary around the easy half:
the shell command, which is a fresh process it controls the launch of. Its own
file tools, its plugin processes and its own parsing of model output sit
outside. Several projects document this explicitly, in their own words, and it
is worth reading those sentences side by side.

## The harnesses

| harness | where the boundary is | who decides a call | default with nothing configured | confines itself |
|---|---|---|---|---|
| [Claude Code][cc-sandbox] | process: Seatbelt on macOS, `bubblewrap` plus an optional seccomp filter on Linux and WSL2; unsandboxed on native Windows | permission rules plus prompts, with named modes | "The sandbox is off by default" | no — "the sandbox wraps shell commands"; built-in file and web tools "follow permission rules instead", and hooks, MCP, LSP and helper commands "run with your full access" |
| [Codex CLI][codex] | process: `sandbox-exec` with a `-p` profile on macOS, "`bwrap` plus `seccomp`" on Linux, the Linux path under WSL2, and "a Windows sandbox implementation" when run natively on Windows | a sandbox mode and an approval policy, as two layers; named [permission profiles][codex-config] sit beside the mode | "the default `workspace-write` sandbox mode", and "the agent runs with network access turned off" | their docs describe the sandbox around commands; a devcontainer is their recommendation, "let Docker provide the outer isolation boundary" |
| [Cursor][cursor-modes] | process: "Seatbelt through `sandbox-exec`" on macOS; on Linux, Landlock with a bubblewrap fallback, inside a user namespace | three Run Modes; in Auto-review a classifier model reviews what the sandbox cannot run | ["By default, terminal commands need your approval"][cursor-security], while [cursor-modes] logs Auto-review as shipped "as the recommended default" in 3.6; [`networkPolicy.default` is `"deny"`][cursor-ref], under a default network mode that adds Cursor's own domain list | their docs scope the sandbox to terminal commands and do not address the editor process |
| [GitHub Copilot CLI][gh-sandbox] | process: ["Microsoft eXecution Container (MXC)"][gh-about], which their docs say "currently sits at the lighter-weight end of this spectrum" and "does not run your commands inside a separate virtual machine or container" | the filesystem policy, three permission levels per path — read/write, read-only, denied | ["Local sandboxing is turned off by default"][gh-about]; once on, "the sandbox is **deny-by-default**" | partly — local MCP and LSP "run inside the sandbox by default", but built-in file tools are "a software-only safeguard rather than one the operating system enforces" |
| [Gemini CLI][gemini-sandbox] | both ends of the range, per platform: Seatbelt — "Lightweight, built-in sandboxing using `sandbox-exec`" — Docker or Podman for "complete process isolation using container technology", and in their repo's docs gVisor and LXC as well | a human per call: `default` is "Prompt for approval on each tool call (default behavior)", with `tools.allowed` as a static bypass and `--yolo` to stop asking | "Sandboxing is disabled by default", opt in with `--sandbox`, `GEMINI_SANDBOX` or `tools.sandbox` | yes, when sandboxing is on: [`security.toolSandboxing`][gemini-config], which "Isolates individual tools instead of the entire CLI process", is documented default `false` |
| [OpenHands][oh-arch] | container, on the paths that use one: "Agent Server and tools run inside the configured container or pod"; the host row of the same table is "directly on the backend host without container isolation" | a [confirmation policy][oh-security] — `AlwaysConfirm`, `NeverConfirm`, `ConfirmRisky` — with risk from a security analyzer | [`OH_CONVERSATION_RUNTIME`][oh-docker] is `local`; "Set to `docker` to run each conversation in its own container" | on the container paths, yes, by construction: the agent server is what is inside. Not wholly — "Agent Canvas and the outer Agent Server stay on the host" |
| [Cline][cline] | none documented | "Auto Approve is evaluated per tool call", against eight permission toggles; "Cline does not use a fixed allowlist. The model marks each command with a `requires_approval` flag based on the command and arguments" | approval required; Auto Approve and YOLO Mode are opt-in | their docs do not describe an OS sandbox |
| [Goose][goose] | none in the permissions docs; Docker appears in a tutorial | four permission modes, where read/write classification "is interpreted by your LLM provider" | "Autonomous Mode is applied by default" | their permissions docs do not describe an OS sandbox |
| [Aider][aider-modes] | none in the options reference | a human, per suggestion; [`--suggest-shell-commands` is on, `--yes-always` turns the asking off][aider-options] | "aider starts in 'code' mode" | their docs do not describe an OS sandbox |
| sandbx | process: Landlock, seccomp and namespaces, derived per run — for the one tool of seven that spawns a program, `bash` | a `CallGate`, by default per tool per run | default-deny at the library level; the CLI opts into three things — read and execute on the system binaries and libraries, a handful of environment variables, and read **and** write on the working directory when no path flag is given, which any path flag replaces rather than adds to; no network | no, and [`SECURITY.md`](../../SECURITY.md) says so as a non-claim |

Five things in that table are worth drawing out.

- **"Off by default" is the most common answer on the third axis.** Claude
  Code's "The sandbox is off by default", Copilot CLI's "Local sandboxing is
  turned off by default", Gemini CLI's "Sandboxing is disabled by default";
  OpenHands' live default is the host rather than a container. A deliberate
  position
  rather than an oversight — a boundary that breaks a build is a boundary people
  turn off permanently — and it is the opposite of sandbx's, which refuses to
  derive a policy at all in some directories rather than run without one.
  One warning about this axis, though: a cell is a summary, and a default is a
  composition of settings rather than one of them. Cursor's security page says
  "By default, terminal commands need your approval" while its Run Modes
  changelog records Auto-review shipping "as the recommended default"; and its
  `networkPolicy.default` of `"deny"` is the action taken when no rule matches,
  under a shipped network mode that layers on "Cursor's built-in defaults for
  common package managers and language tools". Follow the citation before
  relying on the summary.
- **Two projects hand the decision to a model.** Cline's `requires_approval`
  flag is set by the model that proposed the command, and Goose's classification
  of a tool as a write "is interpreted by your LLM provider". Cursor's
  Auto-review mode sends to a classifier whatever the sandbox cannot run, and
  their docs state the consequence themselves: "Auto-review is not a security
  boundary. The classifier can make mistakes."
- **Everyone with a process boundary uses the same two mechanisms.** Seatbelt on
  macOS, and bubblewrap or Landlock on Linux. Claude Code, Codex CLI and Cursor
  reach for all three between them; sandbx uses Landlock directly and does not
  shell out to `bubblewrap`. The mechanism layer below is the same layer for all
  of them. Gemini CLI is the one that spans the whole list rather than picking
  from it — Seatbelt, containers, and in their repo's docs gVisor and LXC — so
  on the first axis it has no single answer, only a per-platform one.
- **The in-process file tool is a shared shape, not a sandbx quirk.** 04's "six
  tools never reach Landlock" has an exact analogue in Copilot CLI's
  documentation, and theirs is the plainest statement of it anybody publishes:
  built-in file tools "check the same filesystem policy before reading or
  writing a file, but because the operating-system sandbox never sees these
  operations, the check is a software-only safeguard rather than one the
  operating system enforces." That is `FsGuard`, described by a different team.
- **Two projects document the harness inside the boundary, and neither gets
  there by default.** OpenHands does it by not having the question on its
  container paths — "Agent Server and tools run inside the configured container
  or pod" — though even there the outer server stays on the host, and the live
  default is the host row of that same table. Gemini CLI does it by scope: its
  sandbox, when you turn it on, takes the whole CLI process, and the setting
  that would narrow it to individual tools is documented default off. Every
  other harness here, sandbx included, confines what it spawns and not itself —
  and most recommend a container or a VM to cover the rest, Claude Code in as
  many words: "To put the tools, processes, and commands in this section behind
  one boundary, run the Claude Code process itself in a container, virtual
  machine, or the sandbox runtime."

## The mechanisms underneath

The harnesses above are built on a small set of primitives, and knowing what
each one is makes the table readable. All of these are documented by their own
projects; none of the descriptions is an assessment.

**Seatbelt, reached through `sandbox-exec`,** is macOS's process-level sandbox,
and it is the one primitive here whose vendor documentation does not describe
the interface the harnesses use. Apple documents [App Sandbox][apple] for macOS
app bundles, where access is gated on entitlements — "App Sandbox provides
protection to system resources and user data by limiting your app’s access to
resources requested through entitlements" — while `sandbox-exec`, which takes a
profile on the command line, has no current page on developer.apple.com; the
archived man page returns a 404, and the Security framework's own navigation
index does not contain the string. So the profile language that Claude Code,
Codex CLI and Cursor all generate is, in practice, documented by those harnesses
rather than by Apple.

**Landlock** is a stackable Linux Security Module, and its
[kernel documentation][landlock] states the property that makes it unusual among
the primitives here:

> Landlock empowers any process, including unprivileged ones, to securely
> restrict themselves.

A ruleset restricts "the thread enforcing it, and its future children", and the
rule types are filesystem hierarchies and TCP or UDP ports. That is the
mechanism sandbx applies in stage 2 of View 1, and it is also the one a harness
would reach for to answer the fourth axis about itself — which is what 04's
first `Worth questioning:` aside is about.

Their page also documents a second mechanism that is *not* a rule type: an IPC
scoping bitmask, set on the ruleset, covering signals sent outside the domain
and connections to abstract unix sockets created outside it. The distinction is
theirs and it is sharp — "IPC scoping does not support exceptions via
landlock_add_rule(2)" — so "Landlock restricts filesystem and network access"
is the rule-type list rather than the whole of what a ruleset can carry. sandbx
withholds both of those by other means — [`SECURITY.md`](../../SECURITY.md)
puts abstract unix sockets under the empty network namespace and signalling
outside the sandbox under the PID namespace — and [09](09-landlock.md) is the
chapter on the rules it does write.

**bubblewrap** builds a sandbox out of unprivileged user namespaces, and its
[README][bwrap] is unusually direct about what it is not:

> bubblewrap is not a complete, ready-made sandbox with a specific security
> policy… the level of protection between the sandboxed processes and the host
> system is entirely determined by the arguments passed to bubblewrap.

It goes further: "Whatever program constructs the command-line arguments for
bubblewrap… is responsible for defining its own security model". That sentence
is the reason "uses bubblewrap" is not an answer on the first axis — it names
the tool and leaves the policy unstated. bubblewrap also records that its setuid
mode has been removed, that it uses `PR_SET_NO_NEW_PRIVS` "to turn off setuid
binaries, which is the traditional way to get out of things like chroots", and
that it "always creates a new mount namespace" while the IPC, PID, network and
UTS namespaces are each listed under "Additionally you can use these kernel
features". The user namespace is not in that opt-in sense optional: it is how
the sandbox exists at all — "Bubblewrap uses these to build the sandbox" — and
what is configurable is the uid and gid treatment inside it. A reader who has
been through 04's three processes will recognise the whole shape: it is the same
sequence sandbx performs itself in its helper stages, as an external binary
instead.

**seccomp-bpf** filters system calls by number and argument. It appears here
only as a layer somebody adds on top of something else — Codex's "`bwrap` plus
`seccomp`", Claude Code's optional filter on Linux, sandbx's own filter in stage
2. No harness in the table uses it as its only boundary.

Above the process primitives sit three container and VM runtimes. None of the
coding harnesses in the table ships one; several recommend one.

**Docker.** Its [security documentation][docker] names four areas to review and
builds isolation from kernel namespaces and cgroups: "Processes running within a
container cannot see, and even less affect, processes running in another
container, or in the host system", and each container gets its own network
stack. Two facts from that page matter when a harness recommends "run it in a
container": the daemon "requires root privileges unless you opt-in to Rootless
mode", and containers start with "a restricted set of capabilities" by default.

**gVisor** is the one that refuses both of the obvious labels. Per
[their docs][gvisor] it is "an application kernel that implements a Linux-like
interface", "written in a memory-safe language (Go)" and running in userspace,
shipped as an OCI runtime called `runsc`. They are explicit that it is "not a
syscall filter (e.g. seccomp-bpf), nor a wrapper over Linux isolation
primitives", and "also not a VM in the everyday sense of the term", but "a
distinct third approach". For the first axis that is a fourth answer: the
boundary is a reimplementation of the kernel interface, so the host kernel is
not the thing the sandboxed program is talking to.

**Firecracker** puts a virtual machine barrier around each workload.
[Their site][firecracker] says it "runs in user space and uses the Linux
Kernel-based Virtual Machine (KVM) to create microVMs", with "only 5 emulated
devices", a boot time under 125 ms and under 5 MiB of overhead per VM. It also
has its own answer to the fourth axis, applied to the VMM rather than to a
harness: "Each Firecracker microVM is further isolated with common Linux
user-space security barriers by a companion program called 'jailer'. The jailer
provides a second line of defense in case the virtualization barrier is ever
compromised."

## A local model moves the prompt, not the boundary

The last family in the field makes privacy rather than confinement the product:
run the model on your own machine, and the conversation never leaves it.
[Ollama][ollama] is the common front end, and its own framing is "Access the
latest open models with complete privacy locally or in the cloud. Your prompts
are never stored or trained on."

Read that sentence carefully, because it spans two deployments: "locally or in
the cloud", and [their cloud documentation][ollama-cloud] is a first-class
option alongside the local one. The claim is about retention and training, not
about the prompt staying on the machine. The two pages are also not the same
claim: the front page says "never stored or trained on", while the cloud page
says "Ollama processes cloud prompts and responses to answer your requests. We
do not use them to train models" — the training half, without the retention
half. Which page you are reading decides what you have been told.

More to the point for this chapter: a local model is orthogonal to all four
axes. [Ollama's own integration list][ollama-integrations] names Claude Code,
Codex CLI, Cline, Goose, VS Code and Zed among the tools that can point at it,
which means a local model is a swap of the thing at the far end of the provider
seam from chapter [02](02-what-a-harness-is.md) — the box labelled "the vendor
boundary" in 04 — and changes nothing about who decides a tool call or what the
tool can reach once it runs. A harness with no boundary and a local model has
moved where the prompt goes. It has not moved the boundary, because there
wasn't one.

## Where sandbx sits, and what it paid

sandbx is the harness in the table that owns its boundary rather than invoking
one, and that is the only unusual thing about its position. Everything else — a
process-level boundary, derived per run, around the tool that spawns a program,
with the harness itself outside it — is the mainstream answer, arrived at
independently by several teams.

Every other row in that table is sourced to somebody else's documentation, which
leaves sandbx's own row the one a reader cannot check by following a link. So
here is where each of its four cells is settled. Nothing below is new mechanism
— each entry is one hop to the chapter that owns it.

| axis | where to check the cell |
|---|---|
| where the boundary is | `BuiltinTool::ALL` in [`sandbx-tools/src/lib.rs`](../../crates/sandbx-tools/src/lib.rs) is the seven, and the `RiskLevel` each `ToolSpec` carries marks the one that executes. `ExecutionContext` in [`context.rs`](../../crates/sandbx-tools/src/context.rs) keeps its policy private and hands out only a configured `sandboxed_command`, which is what makes `bash` the sole road to the kernel; `apply` in [`helper/mod.rs`](../../crates/sandbx-core/src/helper/mod.rs) writes the ruleset and the filter, `isolate` in [`hardening.rs`](../../crates/sandbx-core/src/helper/hardening.rs) the namespaces. [11](11-the-two-seams.md) is the chapter |
| who decides a call | the `CallGate` trait in [`approval.rs`](../../crates/sandbx-agent/src/approval.rs); the `Approve` enum in [`prompt.rs`](../../crates/sandbx-cli/src/agent/prompt.rs) is the two scopes the CLI offers, and the default is the one that answers from argv once per run. [13](13-turn-loop-and-gate.md) is the chapter |
| the default | `SandboxPolicy::default` and `NetworkPolicy`'s `#[default]` variant in [`policy.rs`](../../crates/sandbx-core/src/policy.rs) are the library's deny; `Grants::policy` in [`grants.rs`](../../crates/sandbx-cli/src/grants.rs) is the three things the CLI opts into, and `vetted_root` in [`root.rs`](../../crates/sandbx-cli/src/grants/root.rs) the directories it refuses to derive from. [12](12-a-flag-to-a-kernel-rule.md) is the chapter |
| confines itself | the non-claim in [`SECURITY.md`](../../SECURITY.md) — "The harness process itself is not sandboxed" — and the same fact in the crate's own module doc, which says the helper applies the restrictions "to itself so sandbx is not". [06](06-claims-and-non-claims.md) is the on-ramp |

What it does differently, concretely:

- **It links against Landlock and seccomp rather than shelling out to
  `bubblewrap`.** The policy and the enforcement are in one program, which is
  the thesis in chapter [01](01-what-sandbx-is.md), and it is the direct answer
  to bubblewrap's own "whatever program constructs the command-line arguments…
  is responsible for defining its own security model". sandbx is that program,
  and it is in the same binary as the thing being confined.
- **The default is deny, and some defaults are refusals.** Where three of the
  nearest comparisons ship their sandbox off, a no-flag sandbx run grants a
  named list and nothing else, and in a handful of working directories it
  refuses to derive a policy at all. The whole of that rule is
  [decision-default-policy.md](../decision-default-policy.md).
- **A kernel that cannot enforce the policy is a refusal, not a downgrade.**
  Nothing falls back to running unconfined. The sharp end of that is
  `enforcement_verdict` in
  [`ruleset/compat.rs`](../../crates/sandbx-core/src/helper/ruleset/compat.rs),
  which treats a *partially* applied ruleset as a failure rather than as a
  smaller sandbox, on the reasoning its own error carries — "some access type is
  unrestricted, so the sandbox would not hold". Two of the comparisons document
  the same posture as a choice rather than as the only path: Copilot CLI's docs
  say that on Windows an unsupported feature makes Copilot refuse rather than
  silently weaken its restrictions, and Claude Code documents a
  `failIfUnavailable` setting under which "a missing dependency such as
  bubblewrap on Linux blocks Claude Code from starting rather than falling back
  to unsandboxed execution".

And the bill, which is not small:

- **Linux only.** Seatbelt is not implemented, and the crate refuses a non-Linux
  target at compile time — a `compile_error!` in
  [`sandbx-core/src/lib.rs`](../../crates/sandbx-core/src/lib.rs) whose message
  says why: "no unsandboxed fallback — it is Linux-only by design". Most of the
  harnesses above sandbox on more than one operating system; sandbx runs where
  Landlock does. A container-based design would have cost nothing here, which is
  chapter 01's own `Worth questioning:` aside.
- **Six of the seven tools are enforced in software.** The same shape Copilot
  CLI documents. Choosing to build file tools in-process rather than as
  sandboxed child processes buys speed and loses the kernel as the enforcer, and
  the two enforcement seams in 04 exist because of it.
- **Everything is hand-rolled, including the parts that are not the product.**
  The provider client, the SSE framing and the body serialization from chapter
  [02](02-what-a-harness-is.md) are all code this project maintains so that no
  SDK sits between it and the wire.
- **The harness is unconfined, like almost everyone's.** This is the one line of
  the table where sandbx matches the field and the field is not where anyone
  wants to be. [`SECURITY.md`](../../SECURITY.md) carries it as a non-claim, and
  04 asks whether Landlock's self-restriction property could close it.

## You should now be able to explain

- The four axes, and why "where the boundary is" and "what the default is" are
  design facts rather than judgements.
- Why "it uses bubblewrap" does not answer the first axis, in bubblewrap's own
  words.
- Which projects hand a tool-call decision to a model, and which document the
  consequence of doing so themselves.
- Why the in-process file tool is a shape sandbx shares with at least one
  mainstream harness, and what that costs in both.
- What gVisor means by "a distinct third approach", and why it is neither of the
  two obvious answers on the first axis.
- Which of these projects document the harness itself inside the boundary, the
  structural reason each is able to, and why neither arrives there by default.
- Why reading one page is not enough to answer the third axis, with Cursor's two
  pages as the example.
- Why a local model does not move any of the four axes.
- What sandbx gave up to own its boundary, in two specifics rather than in the
  abstract.
- Where to go in the tree to check each of sandbx's own four cells, rather than
  taking the row on trust.

## Next

[04 — the architecture](04-the-architecture.md), which stops comparing and draws
this one system three times — as processes, as one request's path, and as a set
of named boundaries. Having seen the field, the other thing worth reading early
is what sandbx actually claims: [`SECURITY.md`](../../SECURITY.md), whose "What
sandbx does *not* claim" section is the only part of this comparison the project
is bound by, and [06](06-claims-and-non-claims.md) is the on-ramp to it.

[cc-sandbox]: https://code.claude.com/docs/en/sandboxing
[codex]: https://learn.chatgpt.com/docs/agent-approvals-security
[codex-config]: https://learn.chatgpt.com/docs/config-file/config-basic
[cursor-modes]: https://cursor.com/docs/agent/security/run-modes
[cursor-security]: https://cursor.com/docs/agent/security
[cursor-ref]: https://cursor.com/docs/reference/sandbox
[gh-sandbox]: https://docs.github.com/en/copilot/concepts/agents/copilot-cli/understanding-local-sandboxing
[gh-about]: https://docs.github.com/en/copilot/concepts/security-governance-and-network-settings/about-cloud-and-local-sandboxes
[gemini-sandbox]: https://google-gemini.github.io/gemini-cli/docs/cli/sandbox.html
[gemini-config]: https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md
[oh-arch]: https://docs.openhands.dev/openhands/usage/agent-canvas/architecture
[oh-docker]: https://docs.openhands.dev/openhands/usage/agent-canvas/backend-setup/docker-execution
[oh-security]: https://docs.openhands.dev/sdk/guides/security
[cline]: https://docs.cline.bot/features/auto-approve
[goose]: https://goose-docs.ai/docs/guides/managing-tools/goose-permissions
[aider-modes]: https://aider.chat/docs/usage/modes.html
[aider-options]: https://aider.chat/docs/config/options.html
[apple]: https://developer.apple.com/documentation/security/app-sandbox
[landlock]: https://docs.kernel.org/userspace-api/landlock.html
[bwrap]: https://github.com/containers/bubblewrap
[docker]: https://docs.docker.com/engine/security/
[gvisor]: https://gvisor.dev/docs/
[firecracker]: https://firecracker-microvm.github.io/
[ollama]: https://ollama.com/
[ollama-cloud]: https://docs.ollama.com/cloud
[ollama-integrations]: https://docs.ollama.com/integrations
