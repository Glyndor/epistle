//! PostgreSQL access for the antispam subsystem.
//!
//! The mail server itself is filesystem-first; the database backs only the
//! antispam engine (reputation and, later, the statistical classifier). The
//! pool is created lazily and migrations are applied at startup.

use std::str::FromStr;

use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use crate::config::DatabaseTls;

/// The oldest PostgreSQL major version this release supports.
///
/// 14 is the oldest major still in upstream support today, so the floor is
/// declared once and never derived. [`connect`] enforces it before any
/// migration runs, and the `Database` CI workflow tests against both this
/// floor and the current major so a future query that needs something newer
/// fails as `ServerTooOld` at startup rather than as an SQL syntax error at
/// runtime.
pub const MIN_SERVER_VERSION: u32 = 14;

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
	/// The server reported a `server_version_num` that decodes to a major
	/// older than [`MIN_SERVER_VERSION`]. Refused before migrations run so
	/// the operator learns the version mismatch at startup, not as an SQL
	/// syntax error in the middle of the first query.
	#[error(
		"PostgreSQL {found} is older than the {required} this release requires; \
		 upgrade the server or point [database] at a newer one"
	)]
	ServerTooOld {
		/// The major version `server_version_num` decoded to.
		found: u32,
		/// The [`MIN_SERVER_VERSION`] this release requires.
		required: u32,
	},
	/// `SHOW server_version_num` returned a value that does not decode to a
	/// positive integer. Should not happen against a real PostgreSQL.
	#[error("server_version_num is not a positive integer: {0}")]
	BadServerVersion(String),
}

/// Decode `server_version_num` and check it against `floor`.
///
/// `server_version_num` is the integer PostgreSQL reports from
/// `SHOW server_version_num` (e.g. `140012` for 14.12, `180001` for 18.1).
/// The major is the first two digits: `version_num / 10000`. Returns the
/// major on success, [`DbError::ServerTooOld`] when below the floor, and
/// [`DbError::BadServerVersion`] for any value that does not parse to a
/// positive integer.
fn major_meets_floor(server_version_num: i64, floor: u32) -> Result<u32, DbError> {
	let major: u32 = server_version_num
		.try_into()
		.ok()
		.and_then(|n: u32| n.checked_div(10_000))
		.filter(|&m| m > 0)
		.ok_or_else(|| DbError::BadServerVersion(server_version_num.to_string()))?;
	if major < floor {
		return Err(DbError::ServerTooOld {
			found: major,
			required: floor,
		});
	}
	Ok(major)
}

/// Connect to PostgreSQL and apply all pending migrations. The pool is bounded
/// so a misbehaving database cannot exhaust connections.
///
/// `tls` mirrors the operator-declared TLS preference from the `[database]`
/// config: with [`DatabaseTls::Require`] (the default), every TCP URL is
/// forced to `sslmode=require` at pool-build time, so a future code path that
/// bypasses validation still cannot silently downgrade to plaintext. A
/// Unix-domain socket URL or [`DatabaseTls::Insecure`] leaves the URL's
/// `sslmode` alone; the operator took responsibility for the first, the
/// operator opted into the second.
///
/// Before migrations run, the server's `server_version_num` is checked
/// against [`MIN_SERVER_VERSION`]. A server below the floor is refused with
/// [`DbError::ServerTooOld`] so the operator learns the mismatch at startup
/// rather than as an SQL syntax error in the first query.
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
	let version_text: String = sqlx::query_scalar("SHOW server_version_num")
		.fetch_one(&pool)
		.await
		.map_err(DbError::Connect)?;
	let version_num: i64 = version_text
		.trim()
		.parse()
		.map_err(|_| DbError::BadServerVersion(version_text.clone()))?;
	let major = major_meets_floor(version_num, MIN_SERVER_VERSION)?;
	tracing::info!(
		server_version_num = version_num,
		major,
		"connected to PostgreSQL; major version is at or above the floor"
	);
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

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
