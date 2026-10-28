//! `[database]` validation. Split out of `validate.rs` to keep both files
//! under the per-file line limit, matching the precedent set by the tenant
//! validation in `validate_tenants.rs`.
//!
//! The PostgreSQL connection carries the reputation, the Bayes corpus and, with
//! `directory = true`, the mail accounts. libpq's default `sslmode` is `prefer`,
//! which attempts TLS and silently falls back to plaintext if the server does
//! not offer it. The operator never asked for plaintext and never sees the
//! fallback happen. Validation here makes sure that silent downgrade cannot
//! happen unless the operator has explicitly opted into it (`tls = "insecure"`)
//! or the URL points at a Unix-domain socket, where there is no network on the
//! path to intercept.
//!
//! The `password_file` companion field carries the password outside the URL
//! (the container deployment mounts the secret at a known path) and is
//! validated before the URL: two sources for one secret is refused outright,
//! and the file is opened, `fstat`'d on the open descriptor, read, and
//! stripped of one trailing line ending through the same function
//! (`crate::db::read_password_file_contents`) the pool constructor uses.
//! The same function on both sides means an entry swapped between the
//! validation pass and the connect pass cannot slip past the mode rule,
//! a symlink at the path cannot redirect the read, a FIFO at the path
//! does not block the validator on a writer that never arrives, and a
//! file that contains only a line ending is caught at validation instead
//! of producing a misleading authentication failure at connect. On
//! non-Unix, the kind and mode checks are no-ops and only the I/O
//! surface is preserved.

use std::str::FromStr;

use sqlx::postgres::{PgConnectOptions, PgSslMode};

use super::{Config, ConfigError};
use crate::config::DatabaseTls;
use crate::db::{self, PasswordFileError};

impl Config {
	pub(super) fn validate_database(&self) -> Result<(), ConfigError> {
		let Some(db) = &self.database else {
			return Ok(());
		};

		// A `password_file` companion resolves the secret outside the URL
		// (the recommended container deployment: podup mounts the
		// PostgreSQL password as a read-only secret at a known path). Two
		// sources for one secret would be ambiguous at the pool. Refuse
		// outright, naming both, before anything else reads the file.
		if let Some(path) = &db.password_file {
			if url_carries_password(&db.url) {
				return Err(ConfigError::Invalid(
					"[database] url already carries a password and password_file is also \
					 configured; pick one source (set password_file alone with a URL that \
					 omits the password, or embed the password in url and drop password_file)"
						.into(),
				));
			}
			// The same read function the pool constructor uses: a single
			// function covers the open, the `fstat` on the open
			// descriptor, the read, the trailing-line-ending strip, and
			// the empty refusal, so an entry swapped between the two
			// passes cannot slip past the mode rule, a symlink at the
			// path cannot redirect the read, a FIFO at the path does not
			// block the validator on a writer that never arrives, and a
			// file that contains only a line ending is caught here
			// instead of producing a misleading authentication failure
			// at connect. The trimmed contents are discarded; the
			// connect call reads them again, but on the same shape (the
			// operator would not deploy a secret that depends on the
			// read happening twice).
			if let Err(kind) = db::read_password_file_contents(path) {
				return Err(password_file_error_to_config(path, kind));
			}
		}

		// The operator opted in: the URL is accepted as-is, including a
		// `sslmode=disable`. This is the documented exception for an internal
		// container network with no gateway to the outside.
		if db.tls == DatabaseTls::Insecure {
			return Ok(());
		}

		// Hand the URL to sqlx: the same parser that will run at pool
		// construction time, so we read the same `sslmode` it will. The
		// `socket` field is `Some(_)` for Unix-domain URLs: both the
		// percent-encoded host form (`postgres:///%2Fvar%2Frun%2Fpostgres`)
		// and the query-parameter form (`postgres:///?host=/var/run/...`).
		let opts = PgConnectOptions::from_str(&db.url).map_err(|error| {
			ConfigError::Invalid(format!(
				"[database] url is not a valid Postgres URL: {error}"
			))
		})?;

		// A Unix-domain socket: no network on the wire, so no eavesdropper
		// to defend against. Detected either as the explicit `socket` field
		// (set when the URL uses `host=/path`) or as a `host` that begins
		// with `/` (the percent-encoded host form, `postgres://%2Fpath/...`,
		// which sqlx reads as a socket directory).
		if opts.get_socket().is_some() || opts.get_host().starts_with('/') {
			return Ok(());
		}

		match opts.get_ssl_mode() {
			PgSslMode::Require | PgSslMode::VerifyCa | PgSslMode::VerifyFull => Ok(()),
			other => Err(ConfigError::Invalid(format!(
				"[database] url sslmode must be `require`, `verify-ca`, or `verify-full` \
				 (got `{other:?}`); an absent or weaker sslmode defaults to libpq's \
				 `prefer`, which silently falls back to plaintext if the server does not \
				 offer TLS. Set `tls = \"insecure\"` to assert that the connection stays on \
				 a network you trust, or use a Unix-domain socket URL."
			))),
		}
	}
}

/// Whether the libpq-style URL carries the password itself. Catches both the
/// userinfo form (`postgres://user:pass@host/db`) and the query-parameter form
/// (`postgres://...?password=pass`) that sqlx accepts. A password supplied by
/// `password_file` is supposed to replace the one the URL would otherwise
/// carry; when both are present, the configuration is ambiguous and refused
/// earlier (before this helper runs). Returns `false` when the URL does not
/// parse as a URL at all. The URL-shape error is raised separately by
/// `PgConnectOptions::from_str` below.
fn url_carries_password(url: &str) -> bool {
	let Ok(parsed) = url::Url::parse(url) else {
		return false;
	};
	if parsed.password().is_some() {
		return true;
	}
	parsed.query_pairs().any(|(k, _)| k == "password")
}

/// Map the [`PasswordFileError`] from [`db::read_password_file_contents`]
/// to the `ConfigError` variant the rest of the validator and the
/// existing `validate_tests_j` cases expect: I/O surfaces as
/// `ConfigError::Read` (the same variant a missing config file
/// produces; the `kind` field names the password file so the operator
/// does not see the same wording the config file would have), a
/// non-regular file surfaces as `ConfigError::Invalid` (the refusal
/// message names the path and "regular file"), an insecure mode
/// surfaces as `ConfigError::InsecurePermissions` (the same variant
/// the config file itself uses), and an empty file surfaces as
/// `ConfigError::Invalid` (a configuration problem, not a permission
/// problem).
fn password_file_error_to_config(path: &std::path::Path, kind: PasswordFileError) -> ConfigError {
	match kind {
		PasswordFileError::Io(source) => ConfigError::Read {
			path: path.to_path_buf(),
			source,
			kind: "[database] password_file",
		},
		PasswordFileError::NotRegularFile => ConfigError::Invalid(format!(
			"[database] password_file {} is not a regular file",
			path.display()
		)),
		PasswordFileError::InsecureMode { mode } => ConfigError::InsecurePermissions {
			path: path.to_path_buf(),
			mode,
			kind: "[database] password_file",
		},
		PasswordFileError::Empty => ConfigError::Invalid(format!(
			"[database] password_file {} is empty after stripping the trailing newline",
			path.display()
		)),
	}
}
