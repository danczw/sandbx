# sandbx interview prep: Resources

External links verified 2026-11-16. The kernel docs are tracking release-candidate kernels, so their wording can change.

## Knowledge: the project itself (highest trust, it is the source of truth)

- [SECURITY.md](../../SECURITY.md)
  What is claimed and what is not. Use for: every security answer; the non-claims are the answer to "how would you break it?".
- [README.md](../../README.md)
  The flags, defaults and agent subcommands. Use for: concrete demos and examples.
- [context/guide-sandboxing.md](../../context/guide-sandboxing.md)
  How sandbx-core enforces the policy: the three primitives, the helper, failure handling. Use for: lessons 3–6.
- [context/README.md](../../context/README.md)
  Reading order for the cross-crate docs. Use for: picking the next decision doc.
- `context/decision-*.md`
  Why each cross-crate design went the way it did. Use for: defending design choices (lesson 8).
- Each crate's `//!` header (`crates/*/src/lib.rs`)
  What the crate owns and what it refuses. Use for: the architecture map (lesson 2).

## Knowledge: external

- [Landlock: unprivileged access control (kernel docs)](https://docs.kernel.org/userspace-api/landlock.html)
  Official guide to Landlock's filesystem and network rules. Use for: precise Landlock claims.
- [Linux Sandboxing with Landlock, Mickaël Salaün, OSS 2024 (video)](https://youtu.be/d85TDpv8L9U)
  Talk by Landlock's author. Use for: the best beginner introduction to Landlock. More talks at [landlock.io/talks](https://landlock.io/talks/).
- [LWN: Landlock (finally) sets sail (2021)](https://lwn.net/Articles/859908/)
  Readable overview as merged in 5.13; dated on network rules. Use for: plain-language "what is Landlock".
- [Seccomp BPF (kernel docs)](https://docs.kernel.org/userspace-api/seccomp_filter.html)
  How syscall filtering works and its pitfalls. Key line: "System call filtering isn't a sandbox." Use for: why seccomp is paired with Landlock.
- [LWN: A seccomp overview (2015)](https://lwn.net/Articles/656307/)
  Write-up of Michael Kerrisk's talk. Use for: plain-language "what is seccomp".
- [namespaces(7)](https://man7.org/linux/man-pages/man7/namespaces.7.html), [user_namespaces(7)](https://man7.org/linux/man-pages/man7/user_namespaces.7.html), [pid_namespaces(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html), [network_namespaces(7)](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
  The man pages for each namespace kind. Use for: lesson 3 and 4 definitions.
- [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html)
  Root's powers split into units. Use for: "empty capability sets".
- [No New Privileges flag (kernel docs)](https://docs.kernel.org/userspace-api/no_new_privs.html)
  Why `no_new_privs` must be set before seccomp/Landlock. Use for: lesson 4.
- [openat2(2)](https://man7.org/linux/man-pages/man2/openat2.2.html)
  `RESOLVE_BENEATH` and friends. Use for: lesson 6, FsGuard.
- [Time-of-check to time-of-use (Wikipedia)](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use)
  The race-condition bug class. Lower trust; fine for the definition. Use for: lesson 6.
- [OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
  Direct and indirect prompt injection. Use for: the threat model.
- [Simon Willison: The lethal trifecta for AI agents (2025)](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)
  Private data + untrusted content + external communication = exfiltration. Use for: framing why network and file limits both matter.
- [Anthropic: Beyond permission prompts, making Claude Code more secure and autonomous](https://www.anthropic.com/research/claude-code-sandboxing)
  How a commercial agent sandboxes (bubblewrap, seatbelt, a domain proxy). Use for: comparing sandbx to the industry; note sandbx declines the proxy approach.

## Wisdom (Communities)

Not a priority with one evening before the interview. If wanted later:
- [Landlock mailing list / GitHub discussions via landlock.io](https://landlock.io/)
  Where Landlock's maintainers discuss usage. Use for: checking a sandboxing design with people who built the mechanism.

## Gaps

- No source in the repo explains "why not a container?". The answer in lesson 1 is built from documented facts and is the user's to own.
