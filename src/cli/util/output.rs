//! Printing a `--json` result.

use std::process::ExitCode;

/// Print `value` as the `--json` result on stdout.
pub(in crate::cli) fn print_json(value: &serde_json::Value) -> ExitCode {
	crate::cli::json_out::print(&mut std::io::stdout().lock(), value)
}
