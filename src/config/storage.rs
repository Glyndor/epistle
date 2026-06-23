//! At-rest message-encryption configuration (`[storage]`).

use std::path::PathBuf;

use serde::Deserialize;

/// Storage options, currently the optional at-rest encryption of stored message
/// files. Secure by default: encryption is off, and when turned on the key must
/// be sourced from off the data disk (an environment variable or an
/// operator-managed key file), never auto-generated inside `data_dir`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Storage {
	/// Encrypt new message writes at rest with ChaCha20-Poly1305. Default
	/// `false`. When `true`, a usable 32-byte key must resolve from one of the
	/// key sources below or the server refuses to start (fail closed). This
	/// protects against offline disk/backup theft and complements, not replaces,
	/// full-disk encryption (LUKS).
	#[serde(default)]
	pub encrypt_at_rest: bool,
	/// Name of an environment variable holding the base64-encoded 32-byte key.
	/// Keeps the key out of the config file and off the data disk.
	#[serde(default)]
	pub encryption_key_env: Option<String>,
	/// Path to a file holding the base64-encoded 32-byte key, managed by the
	/// operator (ideally outside `data_dir`). Takes precedence over
	/// `encryption_key_env` when both are set.
	#[serde(default)]
	pub encryption_key_file: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn defaults_to_disabled() {
		let storage: Storage = toml::from_str("").expect("parse empty");
		assert!(!storage.encrypt_at_rest);
		assert!(storage.encryption_key_env.is_none());
		assert!(storage.encryption_key_file.is_none());
	}

	#[test]
	fn parses_key_sources() {
		let storage: Storage = toml::from_str(
			r#"
encrypt_at_rest = true
encryption_key_env = "EPISTLE_STORAGE_KEY"
encryption_key_file = "/etc/epistle/mail.key"
"#,
		)
		.expect("parse");
		assert!(storage.encrypt_at_rest);
		assert_eq!(
			storage.encryption_key_env.as_deref(),
			Some("EPISTLE_STORAGE_KEY")
		);
		assert_eq!(
			storage.encryption_key_file.as_deref(),
			Some(std::path::Path::new("/etc/epistle/mail.key"))
		);
	}

	#[test]
	fn rejects_unknown_keys() {
		assert!(toml::from_str::<Storage>(r#"encrypt = true"#).is_err());
	}
}
