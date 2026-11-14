//! The `[[dkim.domain]]` entry of the configuration file that names a
//! domain's own key, which `epistle dkim split` writes.
//!
//! `epistle domain add` makes the key of a new domain through
//! [`crate::domain::state::edit::add`] and records it in the domain state
//! file instead, since the configuration file is not written for it.

use toml_edit::Value;

use crate::cli::config_edit::ConfigDocument;
use crate::dkim::domain_keys;

/// Write the `[[dkim.domain]]` entry that names `keys` as `name`'s.
pub(in crate::cli) fn add_entry(
	document: &mut ConfigDocument,
	name: &str,
	keys: &domain_keys::DomainKeys,
) -> Result<(), String> {
	let mut fields = vec![
		("selector", Value::from(keys.selector.as_str())),
		("key_file", Value::from(keys.key_file.display().to_string())),
	];
	if let Some((selector, file)) = &keys.rsa {
		fields.push(("rsa_selector", Value::from(selector.as_str())));
		fields.push(("rsa_key_file", Value::from(file.display().to_string())));
	}
	document.upsert_nested_element(&["dkim"], "domain", "name", name, &fields)
}
