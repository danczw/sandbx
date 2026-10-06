//! Applies a sandbox policy to itself, then becomes the requested command.
//!
//! Usage: `sandbx-helper --sandbx-core-exec [POLICY]... -- PROGRAM [ARGS]...`, where the
//! policy flags are whatever [`sandbx_core::HelperArgs`] encodes; that invocation is the
//! supervisor of two stages, the second being [`sandbx_core::HELPER_INNER_FLAG`]'s to
//! describe. A standalone binary so the enforcement path can be tested end-to-end; a
//! shipped sandbx re-execs itself into [`sandbx_core::dispatch_helper_mode`] instead.

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
