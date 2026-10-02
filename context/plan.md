# Plan

A sandboxed coding agent in Rust. Seven crates, at `v0.1.0-alpha.5`.

## Shape

```
sandbx-core      (no internal deps)  ── sandboxing; the only crate allowed to spawn
    └──► sandbx-tools ──┐
                        ├──► sandbx-agent      turn loop
sandbx-providers ───────┘
sandbx-core ──► sandbx-cli                     clap, policy derivation
sandbx-session   placeholder
sandbx-tui       placeholder
```

**`sandbx-cli` does not depend on `sandbx-agent`.** The turn loop exists but is
not reachable from the shipped binary.

## Status

| Phase | State | Note |
|---|---|---|
| 0 — workspace, clippy, deny, hooks | **done** | MSRV never stated; no `rust-version` field anywhere |
| 1 — `sandbx-core` | **done**, beyond plan | two-stage helper, ABI negotiation, capability drops, PID ns |
| 2 — `sandbx-tools` | **done**, extended | 7 tools (not 6), output *and* scan bounds |
| 3 — `sandbx-providers` | **done** | Anthropic + `MockProvider` + SSE, wiremock tests |
| 4 — `sandbx-session` | **not started** | 8-line placeholder, empty `[dependencies]` |
| 5 — `sandbx-agent` | **partial** | loop shipped; no approval gate, no compaction, no persistence |
| 6 — `sandbx-tui` | **not started** | placeholder; no ratatui/crossterm dependency |
| 7 — `sandbx-cli` | **partial** | `sandbox-run` + per-path allowlists ship; no cwd-derived default policy, no `--yolo`, no `auth login` |
| CI | **done** | fmt/clippy/test, sandbox job, cargo-deny, weekly advisories cron |
| Release | **done** | tag-driven musl, x86_64 only; aarch64 still deferred |

### Planned, never built

| Thing | Reality |
|---|---|
| `ApprovalGate`, `RiskLevel`, `ApprovalDecision` | zero occurrences. Nothing gates a tool call. `async_trait` was justified solely by this and is likewise absent |
| `Tool` trait, `ToolRegistry` | a fieldless closed enum and `ALL: [Self; 7]`. The array *is* the registry |
| `Sandbox::new` | `SandboxedCommand` / `SandboxPolicy` |
| naive compaction | `Usage` is observed and dropped |
| per-endpoint egress | `--allow-network` is a bare toggle (#42) |
| `Command::new` CI grep backstop | not added; the clippy lint carries it |

### Changed in flight

- **No `genai`, no `rig-core`** — hand-rolled `reqwest` + `rustls`. (An old
  diagram said "wraps genai"; the decision not to was the one that held.)
- **The agent does not drive `Provider::stream_chat`.** The seam is a closure over
  `EventStream`. #90 asked for this to be settled *before* the loop was written;
  it was written first and the issue is still open.
- **`unsafe_code = "forbid"` workspace-wide**, `sandbx-core` included — the planned
  `deny`-plus-exemption for core was never needed. Zero `unsafe` in the workspace.
- **Clippy exemption is four call sites**, each with a justification, not a
  crate-level allow. Narrower than planned.

## Release log

| Version | For |
|---|---|
| alpha.1–3 | phase completions |
| alpha.4 | **security** — #49 a write grant conferred read; #50 `FsGuard` ignored the executable axis |
| alpha.5 | **security** — #76 a Landlock ruleset accepted while only partly enforced |

The intended rhythm was a release per completed phase. In practice it has become
a release per security fix.

## Open issues worth carrying

| # | |
|---|---|
| #90 | `Provider` is a one-adapter seam; `EventStream` is the real one |
| #89 | audit trail discarded — no crate installs a subscriber |
| #42 | network is on/off only |
| #41 | no design for credentials in sandboxed tool calls |
| #26 | tool calls cannot be cancelled or run in parallel |
| #59, #85 | provider wire shape leaks through a neutral name; thinking blocks unreplayable |
| #87, #88, #91, #92 | untested discrimination paths and dead public surface |

## Credentials

Only tier 1 exists: `ANTHROPIC_API_KEY` via `resolve_api_key`, wrapped in
`secrecy::SecretString`. Keyring (tier 2) and `~/.config/sandbx/credentials.toml`
at `0600` (tier 3) are deferred to whichever phase builds `sandbx auth login`.

## Install

```
cargo install --git https://github.com/danczw/sandbx sandbx-cli
```

The package argument is required — this is a virtual workspace, so the bare form
errors.
