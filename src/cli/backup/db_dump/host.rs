//! The host-side `pg_dump` and `psql` invocations, with the password moved
//! out of the URL and into `PGPASSWORD`.

use crate::config::Database;

use super::{BackupError, CommandSpec};

/// The host-side `pg_dump` invocation. Reads the URL, strips the password
/// if it is in userinfo, and sets `PGPASSWORD` from the URL or from
/// `password_file` (the latter only when the file is readable; the
/// validator already ran, so an unreadable file here surfaces as a
/// password-file I/O error). The argv is `pg_dump <url-without-password>`
/// plus the format flags; the secret never sits in argv.
pub(crate) fn host_pg_dump_spec(db: &Database) -> Result<CommandSpec, BackupError> {
	let (url_without_password, url_password) = split_url_password(&db.url);
	let password = match url_password {
		Some(p) => Some(p),
		None => read_password_from_file(db)?,
	};
	let mut spec = CommandSpec::new(vec![
		"pg_dump".to_string(),
		"-Fp".to_string(),
		"--clean".to_string(),
		"--if-exists".to_string(),
		"--no-owner".to_string(),
		"--no-privileges".to_string(),
		url_without_password,
	]);
	if let Some(password) = password {
		spec = spec.with_env("PGPASSWORD", &password);
	}
	Ok(spec)
}

/// The host-side `psql` invocation for replay. The SQL is fed on stdin
/// because `psql` reads it that way without a temp file. The password is
/// applied through `PGPASSWORD` exactly as `pg_dump` does.
pub(crate) fn host_psql_load_spec(db: &Database, sql: &[u8]) -> Result<CommandSpec, BackupError> {
	let (url_without_password, url_password) = split_url_password(&db.url);
	let from_file = url_password.is_none();
	let password = match url_password {
		Some(p) => Some(p),
		None => read_password_from_file(db)?,
	};
	let mut argv = vec![
		"psql".to_string(),
		"-v".to_string(),
		"ON_ERROR_STOP=1".to_string(),
		"-1".to_string(),
		"-X".to_string(),
	];
	// When the password comes from `password_file`, psql would otherwise
	// prompt on the missing-password URL; pass `--no-password` so it
	// reads `PGPASSWORD` and falls through. With the URL carrying the
	// password already, psql parses it itself and we leave the flag off.
	if from_file && password.is_some() {
		argv.push("--no-password".to_string());
	}
	argv.push(url_without_password);
	let mut spec = CommandSpec::new(argv).with_stdin(sql.to_vec());
	if let Some(password) = password {
		spec = spec.with_env("PGPASSWORD", &password);
	}
	Ok(spec)
}

/// Read the password from `[database] password_file` when set. Returns
/// `None` when the field is unset. The read goes through
/// `crate::db::read_password_file_contents`, the same helper the pool
/// constructor and `Config::validate_database` use; reusing it keeps
/// the trailing-line-ending strip and the empty-secret refusal in one
/// place, so a path that passes the validator and the connect call
/// passes this one too.
fn read_password_from_file(db: &Database) -> Result<Option<String>, BackupError> {
	let Some(path) = &db.password_file else {
		return Ok(None);
	};
	match crate::db::read_password_file_contents(path) {
		Ok(password) => Ok(Some(password)),
		Err(kind) => Err(BackupError::CommandFailed {
			stderr: format!("[database] password_file {}: {kind}", path.display()),
			code: None,
		}),
	}
}

/// Split a libpq URL into the URL-without-password and the password
/// itself. The percent-decoded password is returned next to the
/// password-less URL so the caller can apply it through `PGPASSWORD`.
/// The userinfo form (`postgres://user:pass@host/db`) and the
/// query-parameter form (`postgres://?password=pass`) are both
/// handled. Other query parameters are preserved so a `sslmode=require`
/// or `application_name=epistle` survives the round-trip. A URL that
/// does not parse is returned unchanged with no password; the caller's
/// spawn will surface the URL error.
pub fn split_url_password(url: &str) -> (String, Option<String>) {
	let Ok(mut parsed) = url::Url::parse(url) else {
		return (url.to_string(), None);
	};
	let userinfo_password = parsed.password().map(|encoded| {
		percent_encoding::percent_decode_str(encoded)
			.decode_utf8_lossy()
			.into_owned()
	});
	if userinfo_password.is_some() {
		let _ = parsed.set_password(None);
	}
	let query_password = {
		let mut kept: Vec<(String, String)> = Vec::new();
		let mut password: Option<String> = None;
		for (key, value) in parsed.query_pairs() {
			if key == "password" {
				password = Some(value.into_owned());
			} else {
				kept.push((key.into_owned(), value.into_owned()));
			}
		}
		if password.is_some() {
			parsed.query_pairs_mut().clear();
			for (key, value) in &kept {
				parsed.query_pairs_mut().append_pair(key, value);
			}
		}
		password
	};
	let password = userinfo_password.or(query_password);
	(parsed.to_string(), password)
}
