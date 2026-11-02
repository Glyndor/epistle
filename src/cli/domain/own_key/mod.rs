//! A domain that `epistle domain add` adds signs with a key of its own.
//!
//! The key files go under `<data_dir>/keys/dkim/<domain>/` and a
//! `[[dkim.domain]]` entry names them, so the record the command prints is
//! the domain's own and a leak of another domain's key does not reach it.
//! Without `[dkim]` nothing signs and nothing is made. A dry run names the
//! key and writes nothing.

use std::path::PathBuf;

use toml_edit::Value;

use crate::cli::config_edit::ConfigDocument;
use crate::config::Config;
use crate::dkim::domain_keys;

/// Give `domain` its own key and its `[[dkim.domain]]` entry in `document`,
/// unless the operator asked for the shared `[dkim]` key (`shared`). Returns
/// the key files this call wrote, for [`domain_keys::remove`] when the edit
/// that follows is not committed.
pub(super) fn give(
	config: &Config,
	document: &mut ConfigDocument,
	domain: &str,
	(shared, dry_run): (bool, bool),
	now: u64,
) -> Result<Vec<PathBuf>, String> {
	let Some(dkim) = config.dkim.as_ref().filter(|_| !shared) else {
		return Ok(Vec::new());
	};
	let name = domain.trim().to_ascii_lowercase();
	let dual = dkim.rsa_selector.is_some() && dkim.rsa_key_file.is_some();
	let reserved = domain_keys::reserved_selectors(config)?;
	let (keys, created) = if dry_run {
		(
			domain_keys::planned(&config.data_dir, &name, dual, now, &reserved)?,
			Vec::new(),
		)
	} else {
		domain_keys::ensure(&config.data_dir, &name, dual, now, &reserved)?
	};
	let mut fields = vec![
		("selector", Value::from(keys.selector)),
		("key_file", Value::from(keys.key_file.display().to_string())),
	];
	if let Some((selector, file)) = keys.rsa {
		fields.push(("rsa_selector", Value::from(selector)));
		fields.push(("rsa_key_file", Value::from(file.display().to_string())));
	}
	if let Err(error) = document.upsert_nested_element(&["dkim"], "domain", "name", &name, &fields)
	{
		domain_keys::remove(&created);
		return Err(error);
	}
	Ok(created)
}

/// Remove the key files `created` made for `domain` when the configuration at
/// `path` does not name them: the edit failed before it was saved. When it
/// does (the failure came after the save, while printing or restarting) the
/// keys are the ones the server will load and stay. A configuration that
/// cannot be read keeps them too: deleting a key that may be in use is the
/// worse mistake.
pub(super) fn forget_unused(path: &std::path::Path, domain: &str, created: &[PathBuf]) {
	let persisted = match Config::load(path) {
		Ok(config) => config
			.dkim
			.as_ref()
			.is_some_and(|dkim| dkim.override_for(domain).is_some()),
		Err(_) => true,
	};
	if !persisted {
		domain_keys::remove(created);
	}
}

/// Drop `name`'s `[[dkim.domain]]` entry. A domain that is removed, or an
/// alias that is, leaves no entry naming a domain the server no longer hosts,
/// which the configuration would refuse. The key files stay where they are:
/// they are the operator's to delete once the record is gone.
pub(super) fn drop_entry(document: &mut ConfigDocument, name: &str) -> Result<(), String> {
	document
		.remove_nested_elements(&["dkim"], "domain", "name", name.trim())
		.map(|_| ())
}

#[cfg(test)]
mod tests;
