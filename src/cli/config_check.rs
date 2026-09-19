//! The `config-check` command: validate the configuration file and print
//! "configuration is valid" on success. The body lives here so a test can
//! inject writers for stdout and stderr, instead of going through the
//! process boundary to assert on the single-signature DKIM warning.

use std::process::ExitCode;

use crate::config::Config;

/// Run the `config-check` flow. The argument `config` is the path to a TOML
/// configuration file; `out` and `err` are the destinations for the success
/// line and the single-signature DKIM warning respectively. Returns the exit
/// code the dispatcher should propagate.
pub(super) fn run(
	config: &std::path::Path,
	out: &mut impl std::io::Write,
	err: &mut impl std::io::Write,
) -> ExitCode {
	match Config::load(config) {
		Ok(config) => {
			// Surface the single-signature DKIM advisory on stderr even when
			// the file is otherwise valid. The exit code stays SUCCESS: a
			// warning is not a failure.
			if let Some(warning) = super::serve_tasks::single_signature_dkim_warning(&config) {
				super::style::warn_to(err, warning);
			}
			let _ = writeln!(out, "configuration is valid");
			ExitCode::SUCCESS
		}
		Err(error) => {
			super::style::error_to(err, error);
			ExitCode::FAILURE
		}
	}
}

#[cfg(test)]
#[path = "config_check_tests.rs"]
mod tests;
