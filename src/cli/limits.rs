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
	tenant: Option<&str>,
	value: Option<&str>,
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
		.map_err(|error| format!("{}: {error}", key.name()))?;
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
		(Some(_), None, Key::Quota) => Some("domain_quotas"),
		(Some(_), None, Key::SubmissionRate) => Some("domain_submission_limits"),
		(Some(_), None, _) => {
			return Err("--domain is supported only for quota and submission-rate".into());
		}
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
	let document = edit_document(path, key, None, None, value)?;
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
			Some(0) if matches!(key, Key::MinDataRate) => "disabled".into(),
			Some(value) => match key.unit() {
				values::Unit::Size => format!("{value} bytes"),
				values::Unit::Rate => format!("{value} bytes per second"),
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

/// `limits show --json`: `{"<limit>": {"value", "unit", "source"}, "domain-overrides":
/// {"<domain>": {"submission-rate": N, "quota": N}}, "tenants": {"<name>": {"submission-rate": N}}}`,
/// where `value` is the effective number (`null` when the limit is off or left to
/// the protocol, an array for `queue-backoff`) and `unit` is `bytes`, `bytes-per-second`,
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
			values::Unit::Rate => "bytes-per-second",
			values::Unit::Duration => "seconds",
			values::Unit::Count => "count",
		};
		limits.insert(
			key.name().to_string(),
			serde_json::json!({
				"value": configured
					.or(key.default_value())
					.filter(|value| !(matches!(key, Key::Quota | Key::MinDataRate) && *value == 0)),
				"unit": unit,
				"source": if default { "default" } else { "configured" },
			}),
		);
	}
	// Per-domain overrides for quota and submission-rate.
	let mut domain_overrides = serde_json::Map::new();
	for domain in config
		.domains
		.iter()
		.chain(config.domain_quotas.keys())
		.chain(config.domain_submission_limits.keys())
	{
		let entry = serde_json::json!({
			"quota": config.domain_quotas.get(domain).copied(),
			"submission-rate": config.domain_submission_limits.get(domain).copied(),
		});
		domain_overrides.insert(domain.clone(), entry);
	}
	limits.insert(
		"domain-overrides".to_string(),
		serde_json::Value::Object(domain_overrides),
	);
	// Per-tenant aggregate submission-rate. Other per-tenant limits (quota,
	// max_accounts, max_domains) are accounted for under `[[tenant]]` in the
	// config itself; the CLI surfaces only the operator-editable dial here.
	let mut tenants = serde_json::Map::new();
	for tenant in &config.tenants {
		if let Some(name) = &tenant.name {
			tenants.insert(
				name.clone(),
				serde_json::json!({
					"submission-rate": tenant.submission_rate_limit_per_min,
				}),
			);
		}
	}
	limits.insert("tenants".to_string(), serde_json::Value::Object(tenants));
	serde_json::Value::Object(limits)
}

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
	status: &mut impl Write,
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
					let _ = writeln!(status, "cannot show limits: {error}");
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
		)?;
		if dry_run {
			write!(out, "{}", document.dry_run()?).map_err(|error| error.to_string())?;
			return Ok(ExitCode::SUCCESS);
		}
		let config = document.config()?;
		let outcome = document.commit()?;
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
			return super::config_edit::after_change_with(&config, outcome, true, status, restart);
		}
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
#[path = "limits_tests_config.rs"]
mod tests_config;

#[cfg(test)]
#[path = "limits_tests_domains.rs"]
mod tests_domains;

#[cfg(test)]
#[path = "limits_tests_data_rate.rs"]
mod tests_data_rate;

#[cfg(test)]
#[path = "limits_tests_schedule.rs"]
mod tests_schedule;

#[cfg(test)]
#[path = "limits_tests_queue.rs"]
mod tests_queue;

#[cfg(test)]
#[path = "limits_tests_tenants.rs"]
mod tests_tenants;
