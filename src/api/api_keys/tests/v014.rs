//! A frozen copy of what 0.14.0 reads, so a file 0.15.0 writes is proved to
//! load there and not assumed to. Copied from `src/api/api_keys/mod.rs` at the
//! `v0.14.0` tag: the key as it was (no `grants`), the file, and the loader's
//! scope check. Do not update it to follow the code; it is the other side of
//! the contract.

use serde::{Deserialize, Serialize};

/// 0.14.0's `Scope` names, the only ones its loader accepts.
const V014_SCOPES: [&str; 5] = ["read", "write", "send", "scim", "alias"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct V014Key {
	pub label: String,
	pub hash: String,
	#[serde(default)]
	pub expires_at: Option<u64>,
	#[serde(default)]
	pub ip_cidr: Option<String>,
	#[serde(default)]
	pub scopes: Vec<String>,
	#[serde(default)]
	pub domains: Vec<String>,
	#[serde(default)]
	pub account: Option<String>,
	#[serde(default)]
	pub auto_submitted: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct V014File {
	#[serde(default)]
	pub keys: Vec<V014Key>,
}

/// 0.14.0's `validate_loaded_scopes`: an unknown name refuses the whole file.
fn v014_validate_loaded_scopes(scopes: &[String]) -> std::io::Result<()> {
	for scope in scopes {
		if !V014_SCOPES.contains(&scope.as_str()) {
			return Err(std::io::Error::new(
				std::io::ErrorKind::InvalidData,
				format!("unknown API key scope \"{scope}\" in api_keys.toml"),
			));
		}
	}
	Ok(())
}

/// Load `text` the way 0.14.0 does.
pub(super) fn v014_load(text: &str) -> std::io::Result<V014File> {
	let file: V014File = toml::from_str(text)
		.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
	for key in &file.keys {
		v014_validate_loaded_scopes(&key.scopes)?;
	}
	Ok(file)
}
