//! `epistle antispam`: inspect and edit antispam knobs without regenerating
//! the rest of the configuration.
//!
//! Three list keys (`dnsbl-zones`, `dnsbl-domain-zones`, `dnsbl-url-zones`)
//! accept `set <key> <value...>` to replace and `add|remove <key> <value>` for
//! single membership changes. Every other key accepts `set <key> <value>` to
//! write the mapped TOML field, `unset <key>` to remove it.
//!
//! Secret fields (`llm-endpoint`, `llm-model`, `llm-api-key-env`) are stored
//! on disk only when the operator provides them through an existing channel:
//! `llm-api-key-env` is already the name of an environment variable the
//! server reads at startup. The CLI never accepts a literal key and never
//! prints the configured one back.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use clap::{Subcommand, ValueEnum};

use crate::config::Config;

use super::config_edit::{ConfigDocument, Outcome};
use super::style;

/// All keys the antispam surface accepts. Each maps to the TOML field the
/// loader actually reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Key {
	/// Right-hand-side DNSBL zones (`dnsbl_zones`).
	DnsblZones,
	/// Sender-domain DNSBL zones (`dnsbl_domain_zones`).
	DnsblDomainZones,
	/// URL-host DNSBL zones (`dnsbl_url_zones`).
	DnsblUrlZones,
	/// Greylist deferral window, in seconds (`greylist_delay_secs`).
	GreylistDelay,
	/// First-time sender delay, in seconds (`first_time_sender_delay_secs`).
	FirstTimeSenderDelay,
	/// clamd Unix socket path (`[antispam] clamd_socket`).
	ClamdSocket,
	/// Action on clamd detection (`[antispam] clamd_on_found`).
	ClamdOnFound,
	/// What a scan clamd could not run does (`[antispam] clamd_on_error`).
	ClamdOnError,
	/// clamd exchange timeout, in seconds (`[antispam] clamd_timeout_secs`).
	ClamdTimeout,
	/// clamd maximum message size, in bytes (`[antispam] clamd_max_bytes`).
	ClamdMaxSize,
	/// Scan what local accounts submit (`[antispam] scan_authenticated`).
	ScanAuthenticated,
	/// SubjectPass enabled flag (`[subjectpass] enabled`).
	Subjectpass,
	/// LLM chat-completions endpoint URL (`[antispam_llm] endpoint`).
	LlmEndpoint,
	/// LLM model identifier (`[antispam_llm] model`).
	LlmModel,
	/// LLM API key environment variable name (`[antispam_llm] api_key_env`).
	LlmApiKeyEnv,
	/// Lower bound of the LLM uncertain band (`[antispam_llm] uncertain_low`).
	LlmUncertainLow,
	/// Upper bound of the LLM uncertain band (`[antispam_llm] uncertain_high`).
	LlmUncertainHigh,
}

impl Key {
	fn name(self) -> &'static str {
		match self {
			Self::DnsblZones => "dnsbl-zones",
			Self::DnsblDomainZones => "dnsbl-domain-zones",
			Self::DnsblUrlZones => "dnsbl-url-zones",
			Self::GreylistDelay => "greylist-delay",
			Self::FirstTimeSenderDelay => "first-time-sender-delay",
			Self::ClamdSocket => "clamd-socket",
			Self::ClamdOnFound => "clamd-on-found",
			Self::ClamdOnError => "clamd-on-error",
			Self::ClamdTimeout => "clamd-timeout",
			Self::ClamdMaxSize => "clamd-max-size",
			Self::ScanAuthenticated => "scan-authenticated",
			Self::Subjectpass => "subjectpass",
			Self::LlmEndpoint => "llm-endpoint",
			Self::LlmModel => "llm-model",
			Self::LlmApiKeyEnv => "llm-api-key-env",
			Self::LlmUncertainLow => "llm-uncertain-low",
			Self::LlmUncertainHigh => "llm-uncertain-high",
		}
	}

	fn is_list(self) -> bool {
		matches!(
			self,
			Self::DnsblZones | Self::DnsblDomainZones | Self::DnsblUrlZones
		)
	}
}

/// Show every antispam key in effect.
#[derive(Debug, Subcommand)]
pub enum AntispamCli {
	/// Print every antispam key and its current value (never secrets).
	Show {
		/// Print one JSON object keyed by antispam key.
		#[arg(long)]
		json: bool,
	},
	/// Set one antispam key, or replace a DNSBL list.
	///
	/// Replace the value of a single key (or replace the whole list for the
	/// DNSBL zones). For list keys the trailing values replace the list.
	Set {
		/// The antispam key to set.
		#[arg(value_enum)]
		key: Key,
		/// The new value (single token, or several for list keys).
		#[arg(required = true)]
		value: Vec<String>,
	},
	/// Remove a key, restoring the built-in default.
	///
	/// Refuses for the DNSBL zones; use `remove <key> <value>` to take entries
	/// out one at a time.
	Unset {
		/// The antispam key to remove.
		#[arg(value_enum)]
		key: Key,
	},
	/// Add a single value to a list key (DNSBL zones).
	Add {
		/// The list key to extend. Only DNSBL lists are accepted.
		#[arg(value_enum)]
		key: Key,
		/// The value to insert.
		#[arg(required = true)]
		value: String,
	},
	/// Remove a single value from a list key (DNSBL zones).
	Remove {
		/// The list key to shorten. Only DNSBL lists are accepted.
		#[arg(value_enum)]
		key: Key,
		/// The value to remove.
		#[arg(required = true)]
		value: String,
	},
}

/// Run the chosen antispam action.
pub(super) fn run(path: &Path, action: AntispamCli, dry_run: bool, json: bool) -> ExitCode {
	match execute(path, action, dry_run, json) {
		Ok(code) => code,
		Err(error) => {
			style::error(error);
			ExitCode::FAILURE
		}
	}
}

fn execute(
	path: &Path,
	action: AntispamCli,
	dry_run: bool,
	json: bool,
) -> Result<ExitCode, super::resource::ResourceError> {
	let mut out = std::io::stdout().lock();
	let mut err = style::stderr();
	match action {
		AntispamCli::Show { json: leaf } => {
			let config = Config::load(path)
				.map_err(|e| super::resource::ResourceError::Failure(e.to_string()))?;
			if leaf || json {
				return Ok(super::json_out::print(&mut out, &show::show_json(&config)));
			}
			show_keys(&config, &mut out)
				.map_err(|e| super::resource::ResourceError::Failure(e.to_string()))?;
			Ok(ExitCode::SUCCESS)
		}
		AntispamCli::Set { key, value } => {
			let mut document = open(path)?;
			apply_set(&mut document, key, &value)?;
			commit_reporting(document, key, "set", (dry_run, json), &mut out, &mut err)
		}
		AntispamCli::Unset { key } => {
			let mut document = open(path)?;
			apply_unset(&mut document, key)?;
			commit_reporting(document, key, "unset", (dry_run, json), &mut out, &mut err)
		}
		AntispamCli::Add { key, value } => {
			let mut document = open(path)?;
			apply_add(&mut document, key, &value)?;
			commit_reporting(document, key, "added", (dry_run, json), &mut out, &mut err)
		}
		AntispamCli::Remove { key, value } => {
			let mut document = open(path)?;
			apply_list_remove(&mut document, key, &value)?;
			commit_reporting(
				document,
				key,
				"removed",
				(dry_run, json),
				&mut out,
				&mut err,
			)
		}
	}
}

fn open(path: &Path) -> Result<ConfigDocument, String> {
	ConfigDocument::open(path)
}

/// Validate that `clamd_socket` and `scanner_hook_url` are not set together.
fn validate_no_scanner_conflict(config: &Config, key: Key) -> Result<(), String> {
	if key == Key::ClamdSocket && config.scanner_hook_url.is_some() {
		return Err(
			"clamd-socket and scanner-hook-url cannot be set together: only one scanner per server"
				.into(),
		);
	}
	Ok(())
}

fn apply_set(document: &mut ConfigDocument, key: Key, value: &[String]) -> Result<(), String> {
	// Validate against the current config: the loader refuses
	// scanner_hook_url + clamd_socket, so the CLI must surface that
	// before any edit lands.
	let snapshot = document.config()?;
	validate_no_scanner_conflict(&snapshot, key)?;
	if key.is_list() {
		if value.is_empty() {
			return Err(format!("{} requires at least one value", key.name()));
		}
		set_list_field(document, key, value)?;
	} else if value.len() != 1 {
		return Err(format!(
			"{} takes exactly one value (received {})",
			key.name(),
			value.len()
		));
	} else {
		set_scalar_field(document, key, &value[0])?;
	}
	Ok(())
}

fn apply_unset(document: &mut ConfigDocument, key: Key) -> Result<(), String> {
	if key.is_list() {
		return Err(format!(
			"{} is a list; use `remove {} <value>` to drop entries",
			key.name(),
			key.name()
		));
	}
	unset_scalar_field(document, key)
}

fn apply_add(document: &mut ConfigDocument, key: Key, value: &str) -> Result<(), String> {
	if !key.is_list() {
		return Err(format!(
			"{} is not a list; use `set` to change it",
			key.name()
		));
	}
	let trimmed = value.trim();
	if trimmed.is_empty() {
		return Err("list value must not be empty".into());
	}
	document.add_string(list_field(key), trimmed)?;
	Ok(())
}

fn apply_list_remove(document: &mut ConfigDocument, key: Key, value: &str) -> Result<(), String> {
	if !key.is_list() {
		return Err(format!(
			"{} is not a list; use `unset` to remove it",
			key.name()
		));
	}
	let trimmed = value.trim();
	if trimmed.is_empty() {
		return Err("list value must not be empty".into());
	}
	document.remove_string(list_field(key), trimmed)?;
	Ok(())
}

fn list_field(key: Key) -> &'static str {
	match key {
		Key::DnsblZones => "dnsbl_zones",
		Key::DnsblDomainZones => "dnsbl_domain_zones",
		Key::DnsblUrlZones => "dnsbl_url_zones",
		_ => unreachable!("non-list key asked for its list field name"),
	}
}

fn set_list_field(
	document: &mut ConfigDocument,
	key: Key,
	values: &[String],
) -> Result<(), String> {
	// Replace by removing every current entry, then adding each new one.
	// Reading the current list is done through the validated config so the
	// comment-preserving helpers never see stale state.
	let current = current_list(document, key)?;
	for existing in current {
		document.remove_string(list_field(key), &existing)?;
	}
	for entry in values {
		let trimmed = entry.trim();
		if trimmed.is_empty() {
			return Err("list value must not be empty".into());
		}
		document.add_string(list_field(key), trimmed)?;
	}
	Ok(())
}

fn current_list(document: &ConfigDocument, key: Key) -> Result<Vec<String>, String> {
	let config = document.config()?;
	let list = match list_field(key) {
		"dnsbl_zones" => &config.dnsbl_zones,
		"dnsbl_domain_zones" => &config.dnsbl_domain_zones,
		"dnsbl_url_zones" => &config.dnsbl_url_zones,
		_ => unreachable!(),
	};
	Ok(list.clone())
}

fn set_scalar_field(document: &mut ConfigDocument, key: Key, raw: &str) -> Result<(), String> {
	match key {
		Key::GreylistDelay => {
			let value = parse_duration_seconds(raw).map_err(|e| format!("greylist-delay: {e}"))?;
			document.set_scalar("greylist_delay_secs", value as i64)?;
		}
		Key::FirstTimeSenderDelay => {
			let value =
				parse_duration_seconds(raw).map_err(|e| format!("first-time-sender-delay: {e}"))?;
			document.set_scalar("first_time_sender_delay_secs", value as i64)?;
		}
		Key::ClamdSocket => {
			let trimmed = raw.trim();
			if trimmed.is_empty() {
				return Err("clamd-socket must not be empty".into());
			}
			document.set_table_key(&["antispam"], "clamd_socket", trimmed.to_string())?;
		}
		Key::ClamdOnFound => {
			let lowered = raw.trim().to_ascii_lowercase();
			let value = match lowered.as_str() {
				"quarantine" => "quarantine",
				"reject" => "reject",
				other => {
					return Err(format!(
						"clamd-on-found expected quarantine or reject (got {other:?})"
					));
				}
			};
			document.set_table_key(&["antispam"], "clamd_on_found", value)?;
		}
		Key::ClamdOnError => {
			let lowered = raw.trim().to_ascii_lowercase();
			let value = match lowered.as_str() {
				"accept" => "accept",
				"defer" => "defer",
				other => {
					return Err(format!(
						"clamd-on-error expected accept or defer (got {other:?})"
					));
				}
			};
			document.set_table_key(&["antispam"], "clamd_on_error", value)?;
		}
		Key::ClamdTimeout => {
			let value = parse_u64(raw).map_err(|e| format!("clamd-timeout: {e}"))?;
			document.set_table_key(&["antispam"], "clamd_timeout_secs", value as i64)?;
		}
		Key::ClamdMaxSize => {
			let value = parse_size_bytes(raw).map_err(|e| format!("clamd-max-size: {e}"))?;
			document.set_table_key(&["antispam"], "clamd_max_bytes", value)?;
		}
		Key::ScanAuthenticated => {
			let value = parse_on_off(raw).map_err(|e| format!("scan-authenticated: {e}"))?;
			document.set_table_key(&["antispam"], "scan_authenticated", value)?;
		}
		Key::Subjectpass => {
			let value = parse_on_off(raw).map_err(|e| format!("subjectpass: {e}"))?;
			document.set_table_key(&["subjectpass"], "enabled", value)?;
		}
		Key::LlmEndpoint => {
			let trimmed = raw.trim();
			if trimmed.is_empty() {
				return Err("llm-endpoint must not be empty".into());
			}
			document.set_table_key(&["antispam_llm"], "endpoint", trimmed.to_string())?;
		}
		Key::LlmModel => {
			let trimmed = raw.trim();
			if trimmed.is_empty() {
				return Err("llm-model must not be empty".into());
			}
			document.set_table_key(&["antispam_llm"], "model", trimmed.to_string())?;
		}
		Key::LlmApiKeyEnv => {
			let trimmed = raw.trim();
			if trimmed.is_empty() {
				return Err("llm-api-key-env must not be empty".into());
			}
			document.set_table_key(&["antispam_llm"], "api_key_env", trimmed.to_string())?;
		}
		Key::LlmUncertainLow => {
			let value = parse_unit_interval(raw).map_err(|e| format!("llm-uncertain-low: {e}"))?;
			document.set_table_key(&["antispam_llm"], "uncertain_low", value)?;
		}
		Key::LlmUncertainHigh => {
			let value = parse_unit_interval(raw).map_err(|e| format!("llm-uncertain-high: {e}"))?;
			document.set_table_key(&["antispam_llm"], "uncertain_high", value)?;
		}
		Key::DnsblZones | Key::DnsblDomainZones | Key::DnsblUrlZones => unreachable!(),
	}
	Ok(())
}

fn unset_scalar_field(document: &mut ConfigDocument, key: Key) -> Result<(), String> {
	match key {
		Key::GreylistDelay => document.remove_scalar("greylist_delay_secs"),
		Key::FirstTimeSenderDelay => document.remove_scalar("first_time_sender_delay_secs"),
		Key::ClamdSocket => document.remove_table_key(&["antispam"], "clamd_socket")?,
		Key::ClamdOnFound => document.remove_table_key(&["antispam"], "clamd_on_found")?,
		Key::ClamdOnError => document.remove_table_key(&["antispam"], "clamd_on_error")?,
		Key::ClamdTimeout => document.remove_table_key(&["antispam"], "clamd_timeout_secs")?,
		Key::ClamdMaxSize => document.remove_table_key(&["antispam"], "clamd_max_bytes")?,
		Key::ScanAuthenticated => document.remove_table_key(&["antispam"], "scan_authenticated")?,
		Key::Subjectpass => document.remove_table_key(&["subjectpass"], "enabled")?,
		Key::LlmEndpoint => document.remove_table_key(&["antispam_llm"], "endpoint")?,
		Key::LlmModel => document.remove_table_key(&["antispam_llm"], "model")?,
		Key::LlmApiKeyEnv => document.remove_table_key(&["antispam_llm"], "api_key_env")?,
		Key::LlmUncertainLow => document.remove_table_key(&["antispam_llm"], "uncertain_low")?,
		Key::LlmUncertainHigh => document.remove_table_key(&["antispam_llm"], "uncertain_high")?,
		Key::DnsblZones | Key::DnsblDomainZones | Key::DnsblUrlZones => unreachable!(),
	}
	Ok(())
}

#[cfg(test)]
pub(super) fn commit_and_restart(
	document: ConfigDocument,
	key: Key,
	verb: &str,
	dry_run: bool,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, super::resource::ResourceError> {
	commit_reporting(document, key, verb, (dry_run, false), out, status)
}

/// Write the edit, or with `dry_run` show it, then restart mail. `mode` is
/// `(dry_run, json)`; with `json` the result is one object on `out`.
fn commit_reporting(
	document: ConfigDocument,
	key: Key,
	verb: &str,
	(dry_run, json): (bool, bool),
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, super::resource::ResourceError> {
	let failure = |e: std::io::Error| super::resource::ResourceError::Failure(e.to_string());
	let action = match verb {
		"added" => "add",
		"removed" => "remove",
		other => other,
	};
	let fields = serde_json::json!({ "key": key.name() });
	if dry_run {
		let diff = document.dry_run()?;
		if json {
			let object = super::json_out::dry_run_object(action, fields, diff);
			return writeln!(out, "{object}")
				.map(|()| ExitCode::SUCCESS)
				.map_err(failure);
		}
		write!(out, "{diff}").map_err(failure)?;
		return Ok(ExitCode::SUCCESS);
	}
	let config = document.config()?;
	let outcome = document.commit()?;
	let (code, reload) = if outcome == Outcome::Unchanged {
		writeln!(
			status,
			"antispam {} already set; nothing changed.",
			key.name()
		)
		.map_err(failure)?;
		(ExitCode::SUCCESS, super::json_out::Reload::None)
	} else {
		writeln!(status, "antispam {} {verb}.", key.name()).map_err(failure)?;
		super::config_edit::after_change_reporting(
			&config,
			outcome,
			true,
			status,
			super::stack::run,
		)?
	};
	if json {
		let changed = outcome == Outcome::Changed;
		let object = super::json_out::change_object(action, changed, fields, Some(reload));
		writeln!(out, "{object}").map_err(failure)?;
	}
	Ok(code)
}

/// Cover the LLM secret policy: the endpoint, model and API-key env name are
/// references the loader resolves at runtime; the CLI shows `set` for each,
/// not the value. Kept as a public accessor for the tests.
#[cfg(test)]
pub(crate) fn llm_summary(
	config: &Config,
) -> std::collections::HashMap<&'static str, &'static str> {
	let mut out: std::collections::HashMap<&'static str, &'static str> =
		std::collections::HashMap::new();
	let llm = config.antispam_llm.as_ref();
	out.insert("endpoint", if llm.is_some() { "set" } else { "unset" });
	out.insert("model", if llm.is_some() { "set" } else { "unset" });
	out.insert("api_key_env", if llm.is_some() { "set" } else { "unset" });
	out
}

/// Detect whether the LLM block is present; used by the show path so a future
/// addition does not silently start leaking.
#[cfg(test)]
pub(crate) fn llm_is_set(config: &Config) -> bool {
	config.antispam_llm.is_some()
}

pub mod show;
pub(super) use show::show as show_keys;
use show::{
	parse_duration_seconds, parse_on_off, parse_size_bytes, parse_u64, parse_unit_interval,
};

#[cfg(test)]
mod tests;
