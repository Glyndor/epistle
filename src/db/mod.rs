//! PostgreSQL access for the antispam subsystem.
//!
//! The mail server itself is filesystem-first; the database backs only the
//! antispam engine (reputation and, later, the statistical classifier). The
//! pool is created lazily and migrations are applied at startup.

use std::path::Path;
use std::str::FromStr;

use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use crate::config::DatabaseTls;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

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
	/// `password_file` could not be turned into a usable password: the file
	/// was missing, the file was unreadable, or the file was empty after the
	/// trailing-CR/LF strip. The variant carries the path and the kind, but
	/// never the password itself, the contents reach only the auth call.
	/// epistle never logs or prints the connection options.
	#[error("[database] password_file {path} could not be used: {kind}")]
	PasswordFile {
		/// The path the operator pointed `password_file` at.
		path: std::path::PathBuf,
		/// Why the file could not be used; never carries the contents.
		#[source]
		kind: PasswordFileError,
	},
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
/// `password_file`, when set, names a file holding the database password.
/// the container deployment reads the secret from a podup-mounted
/// `/run/secrets/<name>` rather than embedding it in the URL. The file
/// is opened with `O_NOFOLLOW | O_NONBLOCK` (a symlink at the path is
/// refused with `ELOOP`, a FIFO at the path does not block the pool
/// constructor on a writer that never arrives: `O_NONBLOCK` makes the
/// open return immediately, and the `fstat` that follows refuses the
/// non-regular entry), the open descriptor is `fstat`'d (a non-regular
/// file surfaces as [`PasswordFileError::NotRegularFile`], any group
/// or world bit as [`PasswordFileError::InsecureMode`]), and the
/// contents are read from the same `File`. One trailing line ending
/// (`\n`, or `\r\n` when a Windows editor left the carriage return in
/// place) is stripped and the result is applied to `PgConnectOptions`.
/// An empty password after stripping is refused with
/// [`DbError::PasswordFile`] so a mounted-but-empty secret cannot silently
/// match an unset `PGPASSWORD` or `~/.pgpassfile` row. The URL and the
/// file must not both carry a secret; that check lives in
/// `Config::validate_database` and runs before this function is reached.
/// The validator and the pool constructor share the same
/// `read_password_file_contents` helper (the same `File` is opened,
/// metadata-checked, and read on both paths), so an entry swapped
/// between the validation pass and the connect pass cannot slip past
/// the mode rule, and a symlink at the path cannot redirect the read.
///
/// Before migrations run, the server's `server_version_num` is checked
/// against [`MIN_SERVER_VERSION`]. A server below the floor is refused with
/// [`DbError::ServerTooOld`] so the operator learns the mismatch at startup
/// rather than as an SQL syntax error in the first query.
pub async fn connect(
	url: &str,
	tls: DatabaseTls,
	max_connections: u32,
	password_file: Option<&Path>,
) -> Result<PgPool, DbError> {
	let mut opts: PgConnectOptions =
		PgConnectOptions::from_str(url).map_err(DbError::InvalidUrl)?;
	if let Some(path) = password_file {
		opts = opts.password(&read_password_file(path)?);
	}
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

/// Read the password file at `path` through the same open + `fstat` +
/// read + strip + empty-check chain the pool constructor uses, and
/// return the trimmed password or the [`PasswordFileError`]. The
/// function is `pub(crate)` so `Config::validate_database` can reuse
/// the same path: the validator and the pool constructor stay one
/// code path, and the `password_file` plumbing does not fork in two
/// between configuration and connection. Callers wrap the
/// [`PasswordFileError`] in their own error type ([`DbError::PasswordFile`]
/// at connect, [`ConfigError`] at validation).
///
/// Stripping, empty check, and the open + read against one `File`
/// match the contract `read_password_file` documents below: a single
/// trailing line ending (`\n`, or `\r\n` when a Windows tool left the
/// carriage return in place) is removed, an empty result is refused
/// with [`PasswordFileError::Empty`], and a non-UTF-8 byte sequence
/// surfaces as [`PasswordFileError::Io`] carrying the
/// `InvalidData` error. The validator discards the trimmed string; the
/// connect call discards nothing.
pub(crate) fn read_password_file_contents(path: &Path) -> Result<String, PasswordFileError> {
	use std::io::Read as _;
	let mut file = open_password_file(path)?;
	let mut raw = String::new();
	file.read_to_string(&mut raw)
		.map_err(PasswordFileError::Io)?;
	let trimmed = match raw.strip_suffix('\n') {
		// A `\n` was present at the end. If a `\r` immediately
		// preceded it (the CRLF a Windows editor would leave), drop
		// the `\r` too so the secret is exactly the bytes the
		// operator typed. The conditional order matters: a bare
		// trailing `\r` is not a line ending on its own, and the
		// password may legitimately contain one.
		Some(without_lf) => without_lf
			.strip_suffix('\r')
			.map(str::to_owned)
			.unwrap_or_else(|| without_lf.to_owned()),
		None => raw,
	};
	if trimmed.is_empty() {
		return Err(PasswordFileError::Empty);
	}
	Ok(trimmed)
}

/// Read the password file at `path`, strip one trailing line ending
/// (`\n`, or `\r\n` when a Windows tool left the carriage return in
/// place), and return the resulting password. An empty password after
/// stripping is refused so a mounted-but-empty secret cannot silently
/// match an unset `PGPASSWORD` or `~/.pgpassfile` row. The operator
/// would otherwise see the pool fail with an authentication error
/// against the wrong `user@host` and waste an afternoon on it.
///
/// Only one line ending is stripped. A secret that legitimately ends
/// in a bare `\r` (rare, but possible: a hand-written secret copied
/// from a script) is left alone, because a stray `\r` is the form a
/// CR-only line ending takes and the operator's secret can contain
/// anything except, by deliberate choice, a trailing CR/LF.
///
/// The open, the metadata check, and the read all run against the
/// same `File` (via [`read_password_file_contents`]) so an entry
/// swapped between the validation pass and the read cannot slip a
/// group- or world-readable file past the mode rule, and a symlink at
/// the path cannot redirect the read to a different file. Validation
/// in `Config::validate_database` runs the same function, so the
/// validator and the pool constructor are one code path.
fn read_password_file(path: &Path) -> Result<String, DbError> {
	read_password_file_contents(path).map_err(|kind| DbError::PasswordFile {
		path: path.to_path_buf(),
		kind,
	})
}

/// Open the password file at `path` and return a `File` whose metadata
/// (file kind and mode) has already been checked. The caller reads from
/// this same `File`, so an entry swapped between the open and the read
/// cannot bypass the mode rule. The function is `pub(crate)` so
/// `Config::validate_database` can reuse the same path and the
/// validator and the pool constructor stay one code path; the
/// `password_file` plumbing does not fork in two between configuration
/// and connection.
///
/// On Unix, the open runs with `O_NOFOLLOW | O_NONBLOCK`:
/// `O_NOFOLLOW` makes a symlink at `path` fail with `ELOOP` rather
/// than silently following it to a different file (a symlink the
/// operator did not deploy, pointed at a file the operator did not
/// approve). `O_NONBLOCK` keeps a FIFO at `path` from blocking the
/// pool constructor on a writer that never arrives: a read-only
/// non-blocking open of a FIFO with no writer succeeds on Linux
/// (`ENXIO` is only returned for a write-only `O_NONBLOCK` open), so
/// the open returns immediately and the subsequent `fstat` catches
/// the FIFO (it surfaces as [`PasswordFileError::NotRegularFile`]
/// along with any other non-regular entry, a directory, a device, or
/// a socket). Any group or world bit (`mode & 0o077 != 0`) on the
/// open descriptor surfaces as [`PasswordFileError::InsecureMode`]
/// with the observed mode so the operator sees the bit pattern and
/// the fix. Both checks share the bit rule `Config::load` applies to
/// the config file itself.
///
/// On non-Unix, the open is a plain `File::open` and the file-kind
/// and mode checks are no-ops; only the I/O surface is preserved.
pub(crate) fn open_password_file(path: &Path) -> Result<std::fs::File, PasswordFileError> {
	#[cfg(unix)]
	{
		let file = std::fs::OpenOptions::new()
			.read(true)
			.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
			.open(path)
			.map_err(PasswordFileError::Io)?;
		// `fstat` on the open descriptor, not `metadata` on the path: a
		// race that swaps the entry between the open and the stat cannot
		// change what the descriptor already points at.
		let metadata = file.metadata().map_err(PasswordFileError::Io)?;
		if !metadata.is_file() {
			return Err(PasswordFileError::NotRegularFile);
		}
		let mode = metadata.permissions().mode();
		if mode & 0o077 != 0 {
			return Err(PasswordFileError::InsecureMode { mode: mode & 0o777 });
		}
		Ok(file)
	}
	#[cfg(not(unix))]
	{
		std::fs::File::open(path).map_err(PasswordFileError::Io)
	}
}

/// Why the `password_file` could not be turned into a usable password.
/// Variants stay narrow so a future field carries only the operator-fixable
/// state and not the password itself.
#[derive(Debug, thiserror::Error)]
pub enum PasswordFileError {
	/// The file could not be read: missing file, permission denied, a
	/// symlink at the path with `O_NOFOLLOW` set, the bytes were not
	/// valid UTF-8, or another I/O failure. The kernel's `errno` (or
	/// the I/O error kind) distinguishes the cases; the operator reads
	/// the path and the underlying error.
	#[error("cannot read password file: {0}")]
	Io(#[source] std::io::Error),
	/// The path resolved to something other than a regular file: a
	/// directory, a FIFO, a device, or a socket. Refused so a directory
	/// at the secret path cannot be silently treated as a zero-byte read
	/// (POSIX allows it), and so a FIFO at the path cannot block the
	/// pool constructor on a never-arriving writer.
	#[error("password file is not a regular file")]
	NotRegularFile,
	/// The open file's mode had any group or world bit set (`mode &
	/// 0o077 != 0`). Refused with the observed mode so the operator
	/// sees the bit pattern and the fix. The same bit rule the config
	/// file itself is checked against.
	#[error(
		"password file is group/world-accessible (mode {mode:#o}); \
		 restrict it to owner-only (0600 or 0400)"
	)]
	InsecureMode {
		/// Observed permission mode, masked to `0o777`.
		mode: u32,
	},
	/// The file was read but contained nothing (after the trailing-CR/LF
	/// strip). Refused so a mounted-but-empty secret cannot silently match
	/// an unset `PGPASSWORD`.
	#[error("password file is empty after stripping the trailing newline")]
	Empty,
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
