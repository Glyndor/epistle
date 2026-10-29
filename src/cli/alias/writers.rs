//! `epistle alias`: low-level writers that rewrite the `[[alias]]`
//! array and toggle the disabled-overlay flag.

use std::io::Write;
use std::process::ExitCode;

use crate::config::Config;
use crate::directory_store::AccountStore;

use super::helpers::find_alias;
use crate::cli::config_edit::{ConfigDocument, Outcome};

/// Rewrite the members list on an alias table, preserving the rest.
pub(super) fn upsert_alias_members(
	document: &mut ConfigDocument,
	address: &str,
	members: &[String],
) -> Result<(), String> {
	let mut values = toml_edit::Array::new();
	for member in members {
		values.push(toml_edit::Value::from(member.clone()));
	}
	let key = super::helpers::document_address(document, address);
	document.upsert_element(
		"alias",
		"address",
		&key,
		&[("members", toml_edit::Value::Array(values))],
	)
}

/// Rewrite the senders list on an alias table.
pub(super) fn upsert_alias_senders(
	document: &mut ConfigDocument,
	address: &str,
	senders: &[String],
) -> Result<(), String> {
	let mut values = toml_edit::Array::new();
	for sender in senders {
		values.push(toml_edit::Value::from(sender.clone()));
	}
	let key = super::helpers::document_address(document, address);
	document.upsert_element(
		"alias",
		"address",
		&key,
		&[("senders", toml_edit::Value::Array(values))],
	)
}

/// Validate and commit a config-edit alias mutation.
#[cfg(test)]
pub(crate) fn commit_and_restart(
	document: ConfigDocument,
	address: &str,
	verb: &str,
	dry_run: bool,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, crate::cli::resource::ResourceError> {
	commit_reporting(document, address, verb, (dry_run, false), out, status)
}

/// [`commit_and_restart`] with `(dry_run, json)`: with `json` the result
/// is one object on `out`, its `action` the verb in the present tense
/// (`member added` becomes `member add`).
pub(crate) fn commit_reporting(
	document: ConfigDocument,
	address: &str,
	verb: &str,
	(dry_run, json): (bool, bool),
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, crate::cli::resource::ResourceError> {
	let failure = |e: std::io::Error| crate::cli::resource::ResourceError::Failure(e.to_string());
	let action = verb.replace("added", "add").replace("removed", "remove");
	let fields = serde_json::json!({ "alias": address });
	if dry_run {
		let diff = document.dry_run()?;
		if json {
			let object = crate::cli::json_out::dry_run_object(&action, fields, diff);
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
		writeln!(status, "alias {address} already {verb}; nothing changed.").map_err(failure)?;
		(ExitCode::SUCCESS, crate::cli::json_out::Reload::None)
	} else {
		writeln!(status, "alias {address} {verb}.").map_err(failure)?;
		crate::cli::config_edit::after_change_reporting(
			&config,
			outcome,
			true,
			status,
			crate::cli::stack::run,
		)?
	};
	if json {
		let changed = outcome == Outcome::Changed;
		let object = crate::cli::json_out::change_object(&action, changed, fields, Some(reload));
		writeln!(out, "{object}").map_err(failure)?;
	}
	Ok(code)
}

/// Toggle the disabled flag on a multi-target alias via the dynamic
/// store. This does not flow through the config-edit engine:
/// `aliases.json` lives under `data_dir` and the running server reloads
/// it on the 2 s file watcher, so no restart is required.
#[cfg(test)]
pub(super) fn set_enabled(
	config: &Config,
	address: &str,
	enabled: bool,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, crate::cli::resource::ResourceError> {
	set_enabled_reporting(config, address, enabled, false, out, status)
}

/// [`set_enabled`], printing one JSON object instead of the
/// `address<TAB>state` line when `json` is set.
pub(super) fn set_enabled_reporting(
	config: &Config,
	address: &str,
	enabled: bool,
	json: bool,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, crate::cli::resource::ResourceError> {
	let store = match AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	) {
		Ok(store) => store,
		Err(error) => {
			return Err(crate::cli::resource::ResourceError::Failure(format!(
				"cannot open directory store: {error}"
			)));
		}
	};
	let alias = find_alias(config, address).ok_or_else(|| {
		crate::cli::resource::ResourceError::refused(format!("alias {address} not found"))
	})?;
	match store.set_alias_enabled(&alias.address, enabled) {
		Ok(previous) => {
			let verb = if enabled { "enabled" } else { "disabled" };
			// `previous` is the disabled-state before the call: true means the
			// alias was already disabled. Calling disable twice in a row leaves
			// `previous` = true on the second call and is a no-op (no persist).
			let transition = if previous == !enabled {
				format!("already {verb}")
			} else {
				verb.to_string()
			};
			writeln!(status, "alias {address} {transition}.")
				.map_err(|e| crate::cli::resource::ResourceError::Failure(e.to_string()))?;
			if json {
				let fields = serde_json::json!({ "alias": alias.address, "enabled": enabled });
				let action = if enabled { "enable" } else { "disable" };
				let changed = previous == enabled;
				let object = crate::cli::json_out::change_object(action, changed, fields, None);
				writeln!(out, "{object}")
					.map_err(|e| crate::cli::resource::ResourceError::Failure(e.to_string()))?;
				return Ok(ExitCode::SUCCESS);
			}
			writeln!(
				out,
				"{}\t{}",
				alias.address,
				if enabled { "enabled" } else { "disabled" }
			)
			.map_err(|e| crate::cli::resource::ResourceError::Failure(e.to_string()))?;
			Ok(ExitCode::SUCCESS)
		}
		Err(error) => Err(crate::cli::resource::ResourceError::Failure(format!(
			"cannot update alias {address}: {error}"
		))),
	}
}
