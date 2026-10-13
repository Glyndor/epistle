//! One writer for the `--json` output of `list` and `show` actions.
//!
//! A `list` prints a JSON array and a `show` prints a JSON object, each on
//! one line of stdout, so a script can pipe it into `jq` without caring
//! which resource produced it. Diagnostics never go here: they stay on
//! stderr through `style`.

use std::io::Write;
use std::process::ExitCode;

/// Write `value` as one line of JSON to `out`. A failed write (a closed
/// pipe, a full disk) is an operation failure, exit code 1.
pub(super) fn print(out: &mut impl Write, value: &serde_json::Value) -> ExitCode {
	match writeln!(out, "{value}") {
		Ok(()) => ExitCode::SUCCESS,
		Err(error) => {
			super::style::error(format_args!("writing JSON: {error}"));
			ExitCode::FAILURE
		}
	}
}
