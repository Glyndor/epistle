//! Which database a compose stack's dump and replay act on.

use crate::cli::init::{DATABASE_NAME, DATABASE_USER};
use crate::config::Database;

use super::BackupError;

/// Refuse a `[database] url` that is not the database of the compose stack.
/// With a compose file in the data directory the dump and the replay run
/// inside the stack's `db` service, against the fixed database `epistle init`
/// created. A configuration pointing anywhere else would have its own
/// database ignored: the backup would hold the stack's data and the restore
/// would write into it, both reporting success.
pub(super) fn ensure_stack_database(db: &Database) -> Result<(), BackupError> {
	if is_stack_url(&db.url) {
		Ok(())
	} else {
		Err(BackupError::DatabaseNotInStack)
	}
}

/// True when `url` names the stack's own database: the `epistle` role and
/// database over the socket directory the stack mounts, in the form `init`
/// writes (`postgres://epistle@%2Frun%2Fpostgresql/epistle`). A password or
/// query options do not change which database it is.
fn is_stack_url(url: &str) -> bool {
	let Ok(parsed) = url::Url::parse(url) else {
		return false;
	};
	let host = parsed.host_str().map(|host| {
		percent_encoding::percent_decode_str(host)
			.decode_utf8_lossy()
			.into_owned()
	});
	matches!(parsed.scheme(), "postgres" | "postgresql")
		&& host.as_deref() == Some("/run/postgresql")
		&& parsed.username() == DATABASE_USER
		&& parsed.path() == format!("/{DATABASE_NAME}")
}
