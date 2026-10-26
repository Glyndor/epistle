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
	json: bool,
	out: &mut impl std::io::Write,
	err: &mut impl std::io::Write,
) -> ExitCode {
	match Config::load(config) {
		Ok(config) => {
			// Every advisory goes to stderr even when the file is otherwise
			// valid, and into the `--json` result. The exit code stays
			// SUCCESS: a warning is not a failure.
			let warnings = warnings(&config);
			for warning in &warnings {
				super::style::warn_to(err, warning);
			}
			if json {
				let result = serde_json::json!({ "result": "valid", "warnings": warnings });
				return super::json_out::print(out, &result);
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

/// The advisories about a valid configuration, in the order they print.
fn warnings(config: &Config) -> Vec<String> {
	let mut warnings = Vec::new();
	// The single-signature DKIM advisory.
	if let Some(warning) = super::serve_tasks::single_signature_dkim_warning(config) {
		warnings.push(warning.to_string());
	}
	warnings.extend(super::oauth_advice::advice(config));
	// A value the file sets below a MUST of an RFC, raised when it loaded.
	warnings.extend(config.adjusted.iter().cloned());
	// Capitals in an address or a domain are accepted (epistle uses the
	// lowercase form), but named so the file can be fixed.
	for entry in &config.mixed_case {
		warnings.push(format!(
			"{entry} is not lowercase in the configuration file"
		));
	}
	// An alert that posts to a webhook that is switched off never reaches
	// anybody; say so where the operator looks after an edit.
	if config
		.webhook
		.as_ref()
		.is_some_and(|webhook| !webhook.enabled)
	{
		for alert in config.alerts.iter().filter(|alert| alert.webhook) {
			warnings.push(format!(
				"alert \"{}\" posts to the webhook, which has enabled = false; the alert goes nowhere (`epistle webhook enable`)",
				alert.name
			));
		}
	}
	for domain in super::role_addresses::missing_postmaster(config) {
		warnings.push(format!(
			"{domain} has no postmaster@ address, alias or catch-all; RFC 5321 requires one (`epistle alias add postmaster@{domain} <member>`)"
		));
	}
	warnings
}

#[cfg(test)]
#[path = "config_check_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "config_check_tests_case.rs"]
mod tests_case;

#[cfg(test)]
#[path = "config_check_tests_legacy.rs"]
mod tests_legacy;
