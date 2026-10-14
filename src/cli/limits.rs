//! Server-wide numeric limits in the configuration file.

#[path = "limits_values.rs"]
pub(super) mod values;

#[cfg(test)]
#[path = "limits_tests_values.rs"]
mod tests_values;

#[path = "limits_keys.rs"]
mod keys;
pub use keys::Key;

use crate::config::Config;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

fn edit_document(
	path: &Path,
	key: Key,
	domain: Option<&str>,
	value: Option<&str>,
) -> Result<super::config_edit::ConfigDocument, String> {
	if let Some(table) = key.table() {
		if domain.is_some() {
			return Err("--domain is supported only for quota and submission-rate".into());
		}
		return edit_table_key(path, key, table, value);
	}
	let value = value
		.map(|input| values::parse_value(input, key.unit(), key.max()))
		.transpose()
		.map_err(|error| format!("{}: {error}", key.name()))?;
	let map = match (domain, key) {
		(None, _) => None,
		(Some(_), Key::Quota) => Some("domain_quotas"),
		(Some(_), Key::SubmissionRate) => Some("domain_submission_limits"),
		(Some(_), _) => {
			return Err("--domain is supported only for quota and submission-rate".into());
		}
	};
	let mut document = super::config_edit::ConfigDocument::open(path)?;
	match (map, domain, value) {
		(Some(map), Some(domain), Some(value)) => {
			document.set_map_entry(map, domain, value as i64)?
		}
		(Some(map), Some(domain), None) => document.remove_map_entry(map, domain)?,
		(_, _, Some(value)) => document.set_scalar(key.field(), value as i64)?,
		(_, _, None) => document.remove_scalar(key.field()),
	}
	Ok(document)
}

/// Set or remove a key of a table (`[queue]`); a list key takes its values
/// comma-separated, each checked like a single value.
fn edit_table_key(
	path: &Path,
	key: Key,
	table: &str,
	value: Option<&str>,
) -> Result<super::config_edit::ConfigDocument, String> {
	let parse = |input: &str| {
		values::parse_value(input.trim(), key.unit(), key.max())
			.map_err(|error| format!("{}: {error}", key.name()))
	};
	let mut document = super::config_edit::ConfigDocument::open(path)?;
	match value {
		None => document.remove_table_key(&[table], key.field())?,
		Some(input) if key.is_list() => {
			let mut array = toml_edit::Array::new();
			for part in input.split(',') {
				array.push(parse(part)? as i64);
			}
			document.set_table_key(&[table], key.field(), array)?;
		}
		Some(input) => document.set_table_key(&[table], key.field(), parse(input)? as i64)?,
	}
	Ok(document)
}

#[cfg(test)]
fn change_config(path: &Path, key: Key, value: Option<&str>) -> Result<Option<Config>, String> {
	let document = edit_document(path, key, None, value)?;
	let config = document.config()?;
	Ok((document.commit()? == super::config_edit::Outcome::Changed).then_some(config))
}

fn show(config: &Config, out: &mut impl Write) -> std::io::Result<()> {
	for key in Key::ALL {
		if let Some((values, default)) = key.list(config) {
			let joined: Vec<String> = values.iter().map(u64::to_string).collect();
			let source = if default { "default" } else { "configured" };
			writeln!(
				out,
				"{}\t{} seconds\t{source}",
				key.name(),
				joined.join(",")
			)?;
			continue;
		}
		let configured = key.value(config);
		let default = configured.is_none() || configured == key.default_value();
		let value = match configured.or(key.default_value()) {
			Some(0) if matches!(key, Key::Quota) => "unlimited".into(),
			Some(value) => match key.unit() {
				values::Unit::Size => format!("{value} bytes"),
				values::Unit::Duration => format!("{value} seconds"),
				values::Unit::Count => value.to_string(),
			},
			None if matches!(key, Key::MaxConnectionsPerListener) => "protocol defaults".into(),
			None => "disabled".into(),
		};
		let source = if default { "default" } else { "configured" };
		writeln!(out, "{}\t{value}\t{source}", key.name())?;
	}
	Ok(())
}

/// `limits show --json`: `{"<limit>": {"value", "unit", "source"}}`, where
/// `value` is the effective number (`null` when the limit is off or left to
/// the protocol, an array for `queue-backoff`) and `unit` is `bytes`,
/// `seconds` or `count`.
pub(super) fn show_json(config: &Config) -> serde_json::Value {
	let mut limits = serde_json::Map::new();
	for key in Key::ALL {
		if let Some((values, default)) = key.list(config) {
			limits.insert(
				key.name().to_string(),
				serde_json::json!({
					"value": values,
					"unit": "seconds",
					"source": if default { "default" } else { "configured" },
				}),
			);
			continue;
		}
		let configured = key.value(config);
		let default = configured.is_none() || configured == key.default_value();
		let unit = match key.unit() {
			values::Unit::Size => "bytes",
			values::Unit::Duration => "seconds",
			values::Unit::Count => "count",
		};
		limits.insert(
			key.name().to_string(),
			serde_json::json!({
				"value": configured
					.or(key.default_value())
					.filter(|value| !(matches!(key, Key::Quota) && *value == 0)),
				"unit": unit,
				"source": if default { "default" } else { "configured" },
			}),
		);
	}
	serde_json::Value::Object(limits)
}

#[cfg(test)]
#[path = "limits_tests_config.rs"]
mod tests_config;

/// Operations on the server-wide limits.
#[derive(Debug, clap::Subcommand)]
pub enum Action {
	/// Show effective values and built-in default markers.
	Show {
		/// Print one JSON object keyed by limit name.
		#[arg(long)]
		json: bool,
	},
	/// Save a server-wide limit in the configuration.
	Set {
		/// The limit to configure.
		#[arg(value_enum)]
		key: Key,
		/// Override one domain (quota or submission-rate only).
		#[arg(long)]
		domain: Option<String>,
		/// Non-negative integer, size (K/M/G/T), or duration (s/m/h/d/w);
		/// comma-separated durations for queue-backoff.
		#[arg(allow_hyphen_values = true)]
		value: String,
	},
	/// Remove an override and use the built-in default.
	Unset {
		/// The limit to reset.
		#[arg(value_enum)]
		key: Key,
		/// Remove one domain override (quota or submission-rate only).
		#[arg(long)]
		domain: Option<String>,
	},
}

pub(super) fn run(path: &Path, action: Action, dry_run: bool, out: &mut impl Write) -> ExitCode {
	run_with_restart(
		path,
		action,
		dry_run,
		out,
		&mut super::style::stderr(),
		super::stack::run,
	)
}

fn run_with_restart(
	path: &Path,
	action: Action,
	dry_run: bool,
	out: &mut impl Write,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, super::stack::StackAction) -> ExitCode,
) -> ExitCode {
	let (key, domain, value) = match action {
		Action::Show { json } => {
			let result = Config::load(path)
				.map_err(|error| error.to_string())
				.and_then(|config| {
					if json {
						return writeln!(out, "{}", show_json(&config))
							.map_err(|error| error.to_string());
					}
					show(&config, out).map_err(|error| error.to_string())
				});
			return match result {
				Ok(()) => ExitCode::SUCCESS,
				Err(error) => {
					let _ = writeln!(status, "cannot show limits: {error}");
					ExitCode::FAILURE
				}
			};
		}
		Action::Set { key, domain, value } => (key, domain, Some(value)),
		Action::Unset { key, domain } => (key, domain, None),
	};
	let result = (|| {
		let document = edit_document(path, key, domain.as_deref(), value.as_deref())?;
		if dry_run {
			write!(out, "{}", document.dry_run()?).map_err(|error| error.to_string())?;
			return Ok(ExitCode::SUCCESS);
		}
		let config = document.config()?;
		let outcome = document.commit()?;
		writeln!(
			status,
			"limits {}",
			if outcome == super::config_edit::Outcome::Changed {
				"saved"
			} else {
				"unchanged"
			}
		)
		.map_err(|error| error.to_string())?;
		super::config_edit::after_change_with(&config, outcome, true, status, restart)
	})();
	match result {
		Ok(code) => code,
		Err(error) => {
			let _ = writeln!(status, "cannot update limits: {error}");
			ExitCode::FAILURE
		}
	}
}

#[cfg(test)]
#[path = "limits_tests_cli.rs"]
mod tests_cli;

#[cfg(test)]
#[path = "limits_tests_domains.rs"]
mod tests_domains;

#[cfg(test)]
#[path = "limits_tests_schedule.rs"]
mod tests_schedule;

#[cfg(test)]
#[path = "limits_tests_queue.rs"]
mod tests_queue;
