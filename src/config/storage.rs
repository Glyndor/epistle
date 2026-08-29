//! At-rest message-encryption configuration (`[storage]`) and the pluggable
//! blob store (`[storage.blobs]`).

use std::path::PathBuf;

use serde::Deserialize;

/// Storage options: optional at-rest encryption of stored message files,
/// the retention window for expunged messages, and where uploaded JMAP
/// blobs live. Secure by default: encryption is off, blobs live on the
/// local filesystem. Retention is opt-in (`0` keeps the current behaviour:
/// expunge deletes in the act), so existing deployments are not silently
/// changed.
#[derive(Debug, Clone, Default, Deserialize)]
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
	/// Where uploaded JMAP blobs live. Absent (or `backend = "fs"`) keeps the
	/// historical default of putting them on disk under `<data_dir>/blobs/`;
	/// `backend = "s3"` redirects to a remote bucket.
	#[serde(default)]
	pub blobs: Option<BlobBackendConfig>,
}

/// The blob backend the operator configured under `[storage.blobs]`. Two
/// variants today: `fs` (the default, which is what omitting `[storage.blobs]`
/// already does), and `s3`. Internally tagged by the `backend` key so a TOML
/// `[blobs]` table with `backend = "s3"` plus the S3 fields parses in one
/// step rather than through a wrapping struct.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(tag = "backend", rename_all = "lowercase", deny_unknown_fields)]
pub enum BlobBackendConfig {
	/// On-disk pool under `<data_dir>/blobs/`, sharded by the tail of the id.
	/// This is the default and matches pre-`[storage.blobs]` behaviour
	/// exactly; a config that explicitly writes `backend = "fs"` is equivalent
	/// to leaving the section out.
	#[default]
	Fs,
	/// S3-compatible object storage. `endpoint` is whatever URL the operator
	/// uses (a region-specific `https://s3.<region>.amazonaws.com` or an
	/// S3-compatible service like MinIO), and credentials come from one of
	/// `secret_access_key_env` / `secret_access_key_file` — never inline.
	S3(S3BlobConfig),
}

/// S3-backed blob configuration. `endpoint`, `bucket`, `region` and the
/// access key id are not secrets and live inline; the secret access key
/// comes from one of the two `*_env` / `*_file` paths. A literal
/// `secret_access_key` in the config file is rejected.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3BlobConfig {
	/// S3 endpoint URL (`https://s3.us-east-1.amazonaws.com` or a
	/// compatible service at `http://minio.local:9000`).
	pub endpoint: String,
	/// Bucket name. Object keys inside it are the raw blob id (`<uuid>` for
	/// the payload and `<uuid>.type` / `<uuid>.owner` for the sidecars).
	pub bucket: String,
	/// AWS region (e.g. `us-east-1`). Used for both the SigV4 signing scope
	/// and the canonical request. Setting it wrong means signatures that
	/// look right but the server rejects as `SignatureDoesNotMatch`.
	pub region: String,
	/// Access key id. Public identifier — may sit in the config file. Inline
	/// only; there is no env/file lookup for the access key id, since it is
	/// not a secret.
	pub access_key_id: String,
	/// Environment variable holding the secret access key.
	#[serde(default)]
	pub secret_access_key_env: Option<String>,
	/// Path to a `0600` file holding the secret access key. Takes precedence
	/// over `secret_access_key_env` when both are set.
	#[serde(default)]
	pub secret_access_key_file: Option<PathBuf>,
}

impl S3BlobConfig {
	/// Resolve the secret access key. Order: `secret_access_key_file` (must be
	/// `0600`), then `secret_access_key_env`. Returns `Err` when neither is
	/// set or both yield empty strings. The lit secret is never in the
	/// config; rejecting a config with a lit `secret_access_key = "..."` is
	/// the serde schema's job.
	pub(crate) fn resolve_secret(&self) -> std::io::Result<String> {
		if let Some(path) = &self.secret_access_key_file {
			use std::os::unix::fs::PermissionsExt;
			let meta = std::fs::metadata(path)?;
			if meta.permissions().mode() & 0o077 != 0 {
				return Err(std::io::Error::other(format!(
					"secret_access_key_file {} is group/world-accessible (mode {:#o}); restrict it to 0600",
					path.display(),
					meta.permissions().mode() & 0o777,
				)));
			}
			let value = std::fs::read_to_string(path)?;
			let trimmed = value.trim();
			if trimmed.is_empty() {
				return Err(std::io::Error::other(format!(
					"secret_access_key_file {} is empty",
					path.display()
				)));
			}
			return Ok(trimmed.to_string());
		}
		if let Some(var) = &self.secret_access_key_env {
			let value = std::env::var(var).map_err(|_| {
				std::io::Error::other(format!(
					"storage.blobs: environment variable {var} is not set"
				))
			})?;
			let trimmed = value.trim();
			if trimmed.is_empty() {
				return Err(std::io::Error::other(format!(
					"storage.blobs: environment variable {var} is empty"
				)));
			}
			return Ok(trimmed.to_string());
		}
		Err(std::io::Error::other(
			"storage.blobs s3 backend requires secret_access_key_env or secret_access_key_file",
		))
	}

	/// Build an `S3Backend` from this config, resolving the secret key first
	/// (fail closed on missing credentials).
	pub fn build(&self) -> std::io::Result<crate::storage::blob_backend::S3Backend> {
		let secret = self.resolve_secret()?;
		Ok(crate::storage::blob_backend::S3Backend::new(
			self.endpoint.clone(),
			self.bucket.clone(),
			self.region.clone(),
			self.access_key_id.clone(),
			secret,
		))
	}
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
		// No `[storage.blobs]` section → no override.
		assert!(storage.blobs.is_none());
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

	#[test]
	fn blobs_section_is_optional() {
		// A config without `[storage.blobs]` parses: the historical
		// behaviour (blobs on disk) is the default.
		let storage: Storage = toml::from_str("").expect("parse empty");
		assert!(storage.blobs.is_none());
	}

	#[test]
	fn blobs_fs_backend_parses() {
		let storage: Storage = toml::from_str(
			r#"[blobs]
backend = "fs"
"#,
		)
		.expect("parse fs");
		match storage.blobs.expect("blobs set") {
			BlobBackendConfig::Fs => {}
			BlobBackendConfig::S3(_) => panic!("expected fs"),
		}
	}

	#[test]
	fn blobs_s3_backend_parses_with_env_secret() {
		let storage: Storage = toml::from_str(
			r#"[blobs]
backend = "s3"
endpoint = "https://s3.us-east-1.amazonaws.com"
bucket = "mail-blobs"
region = "us-east-1"
access_key_id = "AKIA-EXAMPLE"
secret_access_key_env = "EPISTLE_S3_SECRET"
"#,
		)
		.expect("parse s3");
		let BlobBackendConfig::S3(s3) = storage.blobs.expect("blobs set") else {
			panic!("expected s3");
		};
		assert_eq!(s3.endpoint, "https://s3.us-east-1.amazonaws.com");
		assert_eq!(s3.bucket, "mail-blobs");
		assert_eq!(s3.region, "us-east-1");
		assert_eq!(s3.access_key_id, "AKIA-EXAMPLE");
		assert_eq!(
			s3.secret_access_key_env.as_deref(),
			Some("EPISTLE_S3_SECRET")
		);
		assert!(s3.secret_access_key_file.is_none());
	}

	#[test]
	fn blobs_s3_backend_rejects_inline_secret() {
		// A literal secret in the config is rejected at the wire level: the
		// schema only knows the env / file shapes, so `secret_access_key =
		// "..."` comes back as an unknown key under `deny_unknown_fields`.
		let result = toml::from_str::<Storage>(
			r#"[blobs]
backend = "s3"
endpoint = "https://s3.us-east-1.amazonaws.com"
bucket = "mail-blobs"
region = "us-east-1"
access_key_id = "AKIA-EXAMPLE"
secret_access_key = "literal-should-not-be-allowed"
"#,
		);
		assert!(
			result.is_err(),
			"a literal secret_access_key must fail to parse"
		);
	}
}
