//! Applies a sandbox policy to itself, then becomes the requested command. Usage:
//! `sandbx-helper --sandbx-core-exec [POLICY]... -- PROGRAM [ARGS]...`, the policy flags
//! being whatever [`sandbx_core::HelperArgs`] encodes, in a two-stage supervisor the second
//! stage ([`sandbx_core::HELPER_INNER_FLAG`]) describes. Standalone so the enforcement path
//! tests end-to-end; a shipped sandbx re-execs into [`sandbx_core::dispatch_helper_mode`] instead.

fn main() -> std::process::ExitCode {
    match sandbx_core::dispatch_helper_mode(std::env::args_os()) {
        sandbx_core::HelperDispatch::Failed(error) => {
            eprintln!("sandbx-helper: {error}");
            std::process::ExitCode::FAILURE
        }
        // This binary has no ordinary mode, so "not helper mode" is a usage error.
        sandbx_core::HelperDispatch::NotHelperMode => {
            eprintln!(
                "sandbx-helper: expected {} as the first argument",
                sandbx_core::HELPER_FLAG
            );
            std::process::ExitCode::FAILURE
        }
    }
}
