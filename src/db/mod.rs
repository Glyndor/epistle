//! PostgreSQL access for the antispam subsystem.
//!
//! The mail server itself is filesystem-first; the database backs only the
//! antispam engine (reputation and, later, the statistical classifier). The
//! pool is created lazily and migrations are applied at startup.

use std::str::FromStr;

use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use crate::config::DatabaseTls;

/// Errors from database setup.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
	/// `sqlx::PgPool` could not establish its initial connection to the URL
	/// (DNS, auth, network, or the server refused). The wrapped
	/// `sqlx::Error` carries the underlying cause.
	#[error("database connection failed: {0}")]
	Connect(#[source] sqlx::Error),
	/// The embedded migration runner could not apply one or more migrations:
	/// the schema is in an inconsistent state, a migration checksum failed,
	/// or the database rejected a statement. The wrapped
	/// `sqlx::migrate::MigrateError` carries the underlying cause.
	#[error("database migration failed: {0}")]
	Migrate(#[source] sqlx::migrate::MigrateError),
	/// The URL could not be parsed into `sqlx::postgres::PgConnectOptions`.
	/// Validation is supposed to catch a malformed URL earlier, so this only
	/// fires on a code path that bypassed validation (a test, for example).
	#[error("database url is not a valid Postgres URL: {0}")]
	InvalidUrl(#[source] sqlx::Error),
}

/// Connect to PostgreSQL and apply all pending migrations. The pool is bounded
/// so a misbehaving database cannot exhaust connections.
///
/// `tls` mirrors the operator-declared TLS preference from the `[database]`
/// config: with [`DatabaseTls::Require`] (the default), every TCP URL is
/// forced to `sslmode=require` at pool-build time, so a future code path that
/// bypasses validation still cannot silently downgrade to plaintext. A
/// Unix-domain socket URL or [`DatabaseTls::Insecure`] leaves the URL's
/// `sslmode` alone — the operator took responsibility for the first, the
/// operator opted into the second.
pub async fn connect(url: &str, tls: DatabaseTls, max_connections: u32) -> Result<PgPool, DbError> {
	let mut opts: PgConnectOptions =
		PgConnectOptions::from_str(url).map_err(DbError::InvalidUrl)?;
	if tls == DatabaseTls::Require && opts.get_socket().is_none() {
		// Belt-and-suspenders: validation already required a stricter
		// `sslmode` for this URL. Forcing it again here means a config that
		// reached this code path without going through validation (or with a
		// future, looser validation) still cannot silently fall back to
		// plaintext.
		opts = opts.ssl_mode(sqlx::postgres::PgSslMode::Require);
	}
	let pool = PgPoolOptions::new()
		.max_connections(max_connections)
		.connect_with(opts)
		.await
		.map_err(DbError::Connect)?;
	migrate(&pool).await?;
	Ok(pool)
}

/// Apply the embedded migrations to an existing pool.
pub async fn migrate(pool: &PgPool) -> Result<(), DbError> {
	sqlx::migrate!("./migrations")
		.run(pool)
		.await
		.map_err(DbError::Migrate)
}
