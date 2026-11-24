//! `epistle alias enable|disable`: the writer of the disabled-overlay flag.

use std::io::Write;
use std::process::ExitCode;

use crate::config::Config;
use crate::directory_store::AccountStore;

use super::helpers::find_alias;

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
