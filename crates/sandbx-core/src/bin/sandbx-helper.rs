//! Applies a sandbox policy to itself, then runs the requested command as its child. Usage:
//! `sandbx-helper --sandbx-core-exec [POLICY]... -- PROGRAM [ARGS]...`, the policy flags
//! being whatever [`sandbx_core::HelperArgs`] encodes, in a two-stage supervisor the second
//! stage ([`sandbx_core::HELPER_INNER_FLAG`]) describes. Standalone so the enforcement path
//! tests end-to-end; a shipped sandbx re-execs into [`sandbx_core::with_helper_dispatch`] instead.

fn main() -> std::process::ExitCode {
    // This binary has no ordinary mode, so "not helper mode" is a usage error.
    sandbx_core::with_helper_dispatch(std::env::args_os(), || {
        eprintln!(
            "sandbx-helper: expected {} as the first argument",
            sandbx_core::HELPER_FLAG
        );
        std::process::ExitCode::FAILURE
    })
}
