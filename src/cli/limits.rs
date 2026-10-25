//! Server-wide numeric limits in the configuration file.

#[path = "limits_values.rs"]
pub(super) mod values;

#[path = "limits_catalog.rs"]
pub(super) mod catalog;

#[path = "limits_protocol.rs"]
mod protocol;

#[path = "limits_show.rs"]
mod show;

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

/// The configuration map that holds the per-domain override of `key`, if
/// the key can be overridden per domain.
pub(super) fn domain_map(key: Key) -> Option<&'static str> {
	match key {
		Key::Quota => Some("domain_quotas"),
		Key::SubmissionRate => Some("domain_submission_limits"),
		_ => None,
	}
}

/// Parse the value of a per-domain override of `key` the way `limits set`
/// does, naming the limit in the error.
pub(super) fn parse_override(key: Key, input: &str) -> Result<u64, String> {
	values::parse_value(input, key.unit(), key.max())
		.map_err(|error| format!("{}: {error}", key.name()))
}

/// Starts the error of a value an Internet standard does not allow, so
/// `run` prints it as the whole line.
const REFUSED_PREFIX: &str = "refused: ";

fn edit_document(
	path: &Path,
	key: Key,
	domain: Option<&str>,
	tenant: Option<&str>,
	value: Option<&str>,
	status_stream: &mut impl Write,
) -> Result<super::config_edit::ConfigDocument, String> {
	if let Some(table) = key.table() {
		if domain.is_some() {
			return Err("--domain is supported only for quota and submission-rate".into());
		}
		if tenant.is_some() {
			return Err("per-tenant limits support submission-rate only".into());
		}
		return edit_table_key(path, key, table, value);
	}
	let value = value
		.map(|input| values::parse_value(input, key.unit(), key.max()))
		.transpose()
		.map_err(|error| match key {
			Key::MaxConnectionsPerListener | Key::MaxHttpConnections => {
				format!("{}: {error}; maximum {} connections", key.name(), key.max())
			}
			_ => format!("{}: {error}", key.name()),
		})?;
	if let (Some(value), Some((floor, reason))) = (value, key.must_floor())
		&& value < floor
	{
		return Err(format!("{REFUSED_PREFIX}{reason}"));
	}
	// SHOULD violations are accepted with a warning: the operator can
	// shorten the queue's give-up window or first retry below what the
	// RFC recommends, but the change is announced so the deviation is
	// visible in the audit trail alongside the saved value.
	if let (Some(value), Some((floor, warning))) = (value, key.should_floor())
		&& value < floor
	{
		let _ = writeln!(status_stream, "warning: {warning}");
	}
	// The limiter reads a zero cap as no limit at all, the opposite of what
	// `set submission-rate 0` looks like it asks for. Removing the limit is
	// `unset`; a cap of zero is refused rather than silently lifting it.
	if matches!(key, Key::SubmissionRate) && value == Some(0) {
		return Err(format!(
			"{}: 0 would remove the limit; use `unset` to remove it",
			key.name()
		));
	}
	// `parse_value` caps every key at or below `i64::MAX`.
	let value_i64 = value.map(|value| i64::try_from(value).unwrap_or(i64::MAX));
	let map = match (domain, tenant, key) {
		(Some(_), Some(_), _) => {
			return Err("--domain and --tenant cannot be combined".into());
		}
		(_, Some(_), _) | (None, None, Key::Quota | Key::SubmissionRate) if tenant.is_some() => {
			return edit_tenant_document(path, key, tenant, value_i64);
		}
		(_, Some(_), _) => {
			return Err("--tenant requires submission-rate".into());
		}
		(Some(_), None, _) => Some(
			domain_map(key).ok_or("--domain is supported only for quota and submission-rate")?,
		),
		(None, None, _) => None,
	};
	let mut document = super::config_edit::ConfigDocument::open(path)?;
	match (map, domain, value_i64) {
		(Some(map), Some(domain), Some(value)) => document.set_map_entry(map, domain, value)?,
		(Some(map), Some(domain), None) => document.remove_map_entry(map, domain)?,
		(_, _, Some(value)) => document.set_scalar(key.field(), value)?,
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

/// Dispatch on `--tenant` and forward to [`edit_tenant`]. Kept in a
/// helper so the per-tenant editing is in one place and the public
/// signature of `edit_document` stays linear.
fn edit_tenant_document(
	path: &Path,
	key: Key,
	tenant: Option<&str>,
	value: Option<i64>,
) -> Result<super::config_edit::ConfigDocument, String> {
	let tenant = match tenant {
		Some(name) => name,
		None => {
			return Err("--tenant is required to edit a per-tenant limit".to_string());
		}
	};
	edit_tenant(path, tenant, key, value)
}

/// Tenant-bounded edit: write `key.field() = value` on the tenant
/// whose `name = tenant`. The tenant must already exist in the
/// config; the operator creates the tenant through `epistle tenant`
/// (or by editing the file) before turning the dial.
fn edit_tenant(
	path: &Path,
	tenant: &str,
	key: Key,
	value: Option<i64>,
) -> Result<super::config_edit::ConfigDocument, String> {
	if !matches!(key, Key::SubmissionRate) {
		return Err("per-tenant limits support submission-rate only".into());
	}
	let mut document = super::config_edit::ConfigDocument::open(path)?;
	let toml_value = value.map(toml_edit::Value::from);
	let edited =
		document.edit_array_entry_field(&["tenant"], tenant, "name", key.field(), toml_value)?;
	if !edited {
		return Err(format!("tenant \"{tenant}\" not found in config"));
	}
	Ok(document)
}

#[cfg(test)]
fn change_config(path: &Path, key: Key, value: Option<&str>) -> Result<Option<Config>, String> {
	let mut sink = Vec::new();
	let document = edit_document(path, key, None, None, value, &mut sink)?;
	let config = document.config()?;
	Ok((document.commit()? == super::config_edit::Outcome::Changed).then_some(config))
}

/// The budget the server derives when `message_memory_budget` is unset, in
/// bytes, and how `limits show` words it. `None` when it is set. The mail
/// container's limit is read from the compose file, as `epistle status`
/// does: this process runs outside the container's cgroup.
fn derived_budget(config: &Config) -> Option<(u64, String)> {
	use crate::smtp::memory_fit;
	if config.message_memory_budget.is_some() {
		return None;
	}
	let limit = memory_fit::compose_or_fallback(&super::stack::compose_path(&config.data_dir));
	let bytes = memory_fit::derive(
		limit.bytes,
		memory_fit::largest_message(config.max_message_size),
	);
	let mib = memory_fit::mib(bytes);
	let text = match limit.source {
		memory_fit::LimitSource::Fallback => {
			format!("auto ({mib} MiB, no mail container limit found, 1g assumed)")
		}
		_ => format!("auto ({mib} MiB from the mail container limit)"),
	};
	Some((bytes, text))
}

/// `limits show` and `limits show --json`: see `limits_show::show` and
/// `limits_show::show_json` for the row shape. These are the thin
/// re-exports so the rest of the CLI keeps the same call site.
pub(super) use show::show;
pub(super) use show::show_json;

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
		/// Override one tenant (submission-rate only).
		#[arg(long, value_name = "TENANT")]
		tenant: Option<String>,
		/// Non-negative integer, size (K/M/G/T), or duration (s/m/h/d/w);
		/// comma-separated durations for queue-backoff.
		#[arg(allow_hyphen_values = true)]
		value: String,
		/// Emit a one-line JSON confirmation on success.
		#[arg(long)]
		json: bool,
	},
	/// Remove an override and use the built-in default.
	Unset {
		/// The limit to reset.
		#[arg(value_enum)]
		key: Key,
		/// Remove one domain override (quota or submission-rate only).
		#[arg(long)]
		domain: Option<String>,
		/// Remove one tenant override (submission-rate only).
		#[arg(long, value_name = "TENANT")]
		tenant: Option<String>,
		/// Emit a one-line JSON confirmation on success.
		#[arg(long)]
		json: bool,
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
	status_stream: &mut impl Write,
	restart: impl FnOnce(&Config, super::stack::StackAction) -> ExitCode,
) -> ExitCode {
	let (key, domain, tenant, value, json) = match action {
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
					let _ = writeln!(status_stream, "cannot show limits: {error}");
					ExitCode::FAILURE
				}
			};
		}
		Action::Set {
			key,
			domain,
			tenant,
			value,
			json,
		} => (key, domain, tenant, Some(value), json),
		Action::Unset {
			key,
			domain,
			tenant,
			json,
		} => (key, domain, tenant, None, json),
	};
	let result = (|| {
		let document = edit_document(
			path,
			key,
			domain.as_deref(),
			tenant.as_deref(),
			value.as_deref(),
			status_stream,
		)?;
		let kind = match &value {
			Some(_) => "set",
			None => "unset",
		};
		let scope = if let Some(domain) = &domain {
			serde_json::json!({"type": "domain", "name": domain})
		} else if let Some(tenant) = &tenant {
			serde_json::json!({"type": "tenant", "name": tenant})
		} else {
			serde_json::json!({"type": "global"})
		};
		if dry_run {
			let diff = document.dry_run()?;
			if json {
				let fields = serde_json::json!({"key": key.name(), "scope": scope});
				let plan = super::json_out::dry_run_object(kind, fields, diff);
				writeln!(out, "{plan}").map_err(|error| error.to_string())?;
			} else {
				write!(out, "{diff}").map_err(|error| error.to_string())?;
			}
			return Ok(ExitCode::SUCCESS);
		}
		let config = document.config()?;
		let outcome = document.commit()?;
		if json {
			let payload = serde_json::json!({
				"result": if outcome == super::config_edit::Outcome::Changed { "saved" } else { "unchanged" },
				"key": key.name(),
				"action": kind,
				"scope": scope,
				"value": value.clone().and_then(|raw| values::parse_value(&raw, key.unit(), key.max()).ok()),
			});
			writeln!(out, "{payload}").map_err(|error| error.to_string())?;
			// The running server applies the change the same way with or
			// without `--json`; its notices go to the status stream, so
			// stdout stays one JSON object.
			return super::config_edit::after_change_with(
				&config,
				outcome,
				true,
				status_stream,
				restart,
			);
		}
		writeln!(
			status_stream,
			"limits {}",
			if outcome == super::config_edit::Outcome::Changed {
				"saved"
			} else {
				"unchanged"
			}
		)
		.map_err(|error| error.to_string())?;
		if key.zero_is_default()
			&& let Some(Ok(0)) = value
				.as_deref()
				.map(|raw| values::parse_value(raw, key.unit(), key.max()))
		{
			let default = key.default_value().unwrap_or(0);
			writeln!(
				status_stream,
				"note: 0 means the default ({default}), not unlimited"
			)
			.map_err(|error| error.to_string())?;
		}
		super::config_edit::after_change_with(&config, outcome, true, status_stream, restart)
	})();
	match result {
		Ok(code) => code,
		Err(error) if error.to_string().starts_with(REFUSED_PREFIX) => {
			let _ = writeln!(status_stream, "{error}");
			ExitCode::from(super::exit::REFUSED)
		}
		Err(error) => {
			let _ = writeln!(status_stream, "cannot update limits: {error}");
			ExitCode::FAILURE
		}
	}
}

#[cfg(test)]
#[path = "limits_tests_config.rs"]
mod tests_config;

#[cfg(test)]
#[path = "limits_tests_domains.rs"]
mod tests_domains;

#[cfg(test)]
#[path = "limits_tests_data_rate.rs"]
mod tests_data_rate;

#[cfg(test)]
#[path = "limits_tests_session_limits.rs"]
mod tests_session_limits;

#[cfg(test)]
#[path = "limits_tests_connection.rs"]
mod tests_connection;

#[cfg(test)]
#[path = "limits_tests_schedule.rs"]
mod tests_schedule;

#[cfg(test)]
#[path = "limits_tests_queue.rs"]
mod tests_queue;

#[cfg(test)]
#[path = "limits_tests_tenants.rs"]
mod tests_tenants;

#[cfg(test)]
#[path = "limits_tests_budget.rs"]
mod tests_budget;

#[cfg(test)]
#[path = "limits_tests_recipients.rs"]
mod tests_recipients;

#[cfg(test)]
#[path = "limits_tests_should_warn.rs"]
mod tests_should_warn;

#[cfg(test)]
#[path = "limits_tests_catalog.rs"]
mod tests_catalog;

#[cfg(test)]
#[path = "limits_tests_protocol.rs"]
mod tests_protocol;
