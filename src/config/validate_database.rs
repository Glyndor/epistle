//! `[database]` validation. Split out of `validate.rs` to keep both files
//! under the per-file line limit, matching the precedent set by the tenant
//! validation in `validate_tenants.rs`.
//!
//! The PostgreSQL connection carries the reputation, the Bayes corpus and, with
//! `directory = true`, the mail accounts. libpq's default `sslmode` is `prefer`,
//! which attempts TLS and silently falls back to plaintext if the server does
//! not offer it — the operator never asked for plaintext and never sees the
//! fallback happen. Validation here makes sure that silent downgrade cannot
//! happen unless the operator has explicitly opted into it (`tls = "insecure"`)
//! or the URL points at a Unix-domain socket, where there is no network on the
//! path to intercept.

use std::str::FromStr;

use sqlx::postgres::{PgConnectOptions, PgSslMode};

use super::{Config, ConfigError};
use crate::config::DatabaseTls;

impl Config {
	pub(super) fn validate_database(&self) -> Result<(), ConfigError> {
		let Some(db) = &self.database else {
			return Ok(());
		};

		// The operator opted in: the URL is accepted as-is, including a
		// `sslmode=disable`. This is the documented exception for an internal
		// container network with no gateway to the outside.
		if db.tls == DatabaseTls::Insecure {
			return Ok(());
		}

		// Hand the URL to sqlx: the same parser that will run at pool
		// construction time, so we read the same `sslmode` it will. The
		// `socket` field is `Some(_)` for Unix-domain URLs — both the
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
