//! At-rest message-encryption configuration (`[storage]`).

use std::path::PathBuf;

use serde::Deserialize;

/// Storage options: optional at-rest encryption of stored message files and
/// the retention window for expunged messages. Secure by default: encryption
/// is off, and when turned on the key must be sourced from off the data disk
/// (an environment variable or an operator-managed key file), never
/// auto-generated inside `data_dir`. Retention is opt-in (`0` keeps the current
/// behaviour: expunge deletes in the act), so existing deployments are not
/// silently changed.
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
	/// Days to keep expunged messages in the per-account archive
	/// (`<account>/.archive/`) before the hourly sweeper removes them. `0`
	/// (default) keeps the current behaviour: an expunge deletes the on-disk
	/// files immediately. Setting this to a positive value moves expunged
	/// messages into the archive instead of deleting them, and lets operators
	/// restore them via `epistle archive restore` or
	/// `POST /api/v1/accounts/{name}/archive/{id}/restore`. Archive entries
	/// count toward the account's quota (a stored message is still a stored
	/// message).
	#[serde(default)]
	pub deleted_retention_days: u64,
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
		// The current behaviour is the default: zero days retention, so
		// expunge deletes in the act.
		assert_eq!(storage.deleted_retention_days, 0);
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
	fn parses_retention_days() {
		let storage: Storage = toml::from_str("deleted_retention_days = 30").expect("parse");
		assert_eq!(storage.deleted_retention_days, 30);
	}

	#[test]
	fn rejects_unknown_keys() {
		assert!(toml::from_str::<Storage>(r#"encrypt = true"#).is_err());
	}
}
