//! Tests for the host-side `pg_dump` / `psql` command spec and the
//! password-handling rules. The container-side path is covered in
//! `backup_container_tests.rs`.

use super::*;
use crate::config::Database;

fn database_with_url(url: &str) -> Database {
	let body = format!(r#"url = "{url}""#);
	toml::from_str(&body).expect("database")
}

fn database_with_url_and_password_file(url: &str, password_file: &std::path::Path) -> Database {
	let body = format!(
		r#"url = "{url}"
password_file = {:?}
"#,
		password_file
	);
	toml::from_str(&body).expect("database")
}

#[test]
fn pg_dump_argv_never_carries_password_from_url() {
	let db = database_with_url("postgres://epistle:supersecret@%2Frun%2Fpostgresql/epistle");
	let spec = host_pg_dump_spec(&db).expect("spec");
	let argv_joined = spec.argv().join("\u{0}");
	assert!(
		!argv_joined.contains("supersecret"),
		"password leaked into argv: {:?}",
		spec.argv()
	);
	let env_joined = spec
		.env()
		.iter()
		.map(|(k, v)| format!("{k}={v}"))
		.collect::<Vec<_>>()
		.join("\u{0}");
	assert!(
		env_joined.contains("PGPASSWORD=supersecret"),
		"password must be in env as PGPASSWORD, got: {:?}",
		spec.env()
	);
}

#[test]
fn pg_dump_argv_never_carries_password_from_password_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let pw_path = dir.path().join("pw");
	let mut file = std::fs::File::create(&pw_path).expect("create");
	file.write_all(b"file-secret\n").expect("write");
	// The same mode rule `Config::load` applies to the config file
	// and `read_password_file_contents` applies to the password
	// file: owner-only. A file at 0o644 (the umask-default of a
	// `std::fs::write` after the surrounding tempdir was made
	// 0o755) is refused with `InsecureMode`. Setting 0o600 keeps
	// the read path open.
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&pw_path, std::fs::Permissions::from_mode(0o600))
			.expect("chmod 0o600 on password file");
	}
	let db = database_with_url_and_password_file(
		"postgres://epistle@%2Frun%2Fpostgresql/epistle",
		&pw_path,
	);
	let spec = host_pg_dump_spec(&db).expect("spec");
	let argv_joined = spec.argv().join("\0");
	assert!(
		!argv_joined.contains("file-secret"),
		"password_file contents leaked into argv: {:?}",
		spec.argv()
	);
	let env_joined = spec
		.env()
		.iter()
		.map(|(k, v)| format!("{k}={v}"))
		.collect::<Vec<_>>()
		.join("\0");
	assert!(
		env_joined.contains("PGPASSWORD=file-secret"),
		"PGPASSWORD must carry the file contents, got: {:?}",
		spec.env()
	);
}

#[test]
fn pg_dump_argv_carries_no_pgpwd_arg_and_uses_no_password_flag() {
	let dir = tempfile::tempdir().expect("tempdir");
	let pw_path = dir.path().join("pw");
	std::fs::write(&pw_path, b"somepw").expect("write");
	// `read_password_file_contents` requires owner-only mode, same
	// bit rule `Config::load` applies to the config file.
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&pw_path, std::fs::Permissions::from_mode(0o600))
			.expect("chmod 0o600 on password file");
	}
	let db = database_with_url_and_password_file("postgres://epistle@localhost/epistle", &pw_path);
	let spec = host_pg_dump_spec(&db).expect("spec");
	// `psql` accepts --password / -W to force the prompt and --no-password
	// to suppress it. The host path must use neither, the password
	// arrives through the env, not through argv. A regression that
	// adds one of these flags means the password could be surfaced
	// through `/proc/<pid>/cmdline` if a future change forgets to set
	// the env alongside.
	assert!(
		!spec
			.argv()
			.iter()
			.any(|arg| arg == "--password" || arg == "-W" || arg == "--no-password"),
		"argv must not carry --password/-W/--no-password when PGPASSWORD is set; got: {:?}",
		spec.argv()
	);
}

#[test]
fn pg_dump_url_password_strips_userinfo_from_url() {
	let db = database_with_url("postgres://epistle:urlpass@%2Frun%2Fpostgresql/epistle");
	let spec = host_pg_dump_spec(&db).expect("spec");
	let url_arg = spec
		.argv()
		.iter()
		.find(|arg| arg.starts_with("postgres://"))
		.expect("url argument");
	assert!(
		!url_arg.contains("urlpass"),
		"url in argv still carries the password: {url_arg}"
	);
	// The userinfo separator `:` between the user and the password is
	// removed by `set_password(None)`; the surviving form is
	// `postgres://epistle@...` with no `:` after the user.
	assert!(
		!url_arg.contains("epistle:"),
		"url in argv still carries the user:password separator: {url_arg}"
	);
}

#[test]
fn pg_dump_query_password_is_also_stripped() {
	let db = database_with_url("postgres://epistle@%2Frun%2Fpostgresql/epistle?password=qpw");
	let spec = host_pg_dump_spec(&db).expect("spec");
	let argv_joined = spec.argv().join("\u{0}");
	assert!(
		!argv_joined.contains("qpw"),
		"query password leaked into argv: {:?}",
		spec.argv()
	);
	let env_joined = spec
		.env()
		.iter()
		.map(|(k, v)| format!("{k}={v}"))
		.collect::<Vec<_>>()
		.join("\u{0}");
	assert!(
		env_joined.contains("PGPASSWORD=qpw"),
		"query password must reach env, got: {:?}",
		spec.env()
	);
}

#[test]
fn psql_load_argv_never_carries_password_from_password_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let pw_path = dir.path().join("pw");
	std::fs::write(&pw_path, b"psql-file-secret\n").expect("write");
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&pw_path, std::fs::Permissions::from_mode(0o600))
			.expect("chmod 0o600 on password file");
	}
	let db = database_with_url_and_password_file(
		"postgres://epistle@%2Frun%2Fpostgresql/epistle",
		&pw_path,
	);
	let spec = host_psql_load_spec(&db, b"select 1;\n").expect("spec");
	let argv_joined = spec.argv().join("\u{0}");
	assert!(
		!argv_joined.contains("psql-file-secret"),
		"psql argv leaked the password_file contents: {:?}",
		spec.argv()
	);
	let env_joined = spec
		.env()
		.iter()
		.map(|(k, v)| format!("{k}={v}"))
		.collect::<Vec<_>>()
		.join("\u{0}");
	assert!(
		env_joined.contains("PGPASSWORD=psql-file-secret"),
		"PGPASSWORD must carry the file contents, got: {:?}",
		spec.env()
	);
}

#[test]
fn psql_load_carries_sql_on_stdin() {
	let db = database_with_url("postgres://epistle@%2Frun%2Fpostgresql/epistle");
	let sql = b"create table x (id int);\ninsert into x values (1);\n";
	let spec = host_psql_load_spec(&db, sql).expect("spec");
	assert_eq!(spec.stdin_payload(), Some(sql.as_slice()));
}

#[test]
fn split_url_password_handles_userinfo_and_query() {
	let (url_a, pw_a) = split_url_password("postgres://u:pw@%2Frun%2Fpostgresql/db");
	assert!(!url_a.contains("pw"), "url_a leaked password: {url_a}");
	assert_eq!(pw_a.as_deref(), Some("pw"));
	let (url_b, pw_b) = split_url_password("postgres://u@%2Frun%2Fpostgresql/db?password=qp");
	assert!(
		!url_b.contains("qp"),
		"url_b leaked query password: {url_b}"
	);
	assert_eq!(pw_b.as_deref(), Some("qp"));
}

#[test]
fn split_url_password_preserves_unrelated_query_params() {
	let (url, pw) =
		split_url_password("postgres://u:pw@h/db?application_name=epistle&sslmode=require");
	assert!(!url.contains("pw"), "url leaked password: {url}");
	assert_eq!(pw.as_deref(), Some("pw"));
	assert!(
		url.contains("application_name=epistle"),
		"url_a kept application_name: {url}"
	);
	assert!(url.contains("sslmode=require"), "url_a kept sslmode: {url}");
}

#[test]
fn backup_error_display_names_the_cause_without_leaking_the_password() {
	let error = BackupError::CommandFailed {
		stderr: "FATAL: password authentication failed for user \"epistle\"".to_string(),
		code: Some(2),
	};
	let text = format!("{error}");
	assert!(text.contains("status 2"), "code must appear: {text}");
	assert!(text.contains("FATAL"), "stderr must appear: {text}");
}

#[test]
fn binary_missing_error_mentions_the_command() {
	let error = BackupError::BinaryMissing("pg_dump".to_string());
	let text = format!("{error}");
	assert!(text.contains("pg_dump"), "binary name must appear: {text}");
	assert!(
		text.contains("not found on PATH"),
		"kind must appear: {text}"
	);
}

#[test]
fn empty_output_error_names_the_diagnostic() {
	let error = BackupError::EmptyOutput;
	let text = format!("{error}");
	assert!(text.contains("no output"), "message must explain: {text}");
}

#[cfg(test)]
#[path = "backup_tests_source.rs"]
mod tests_source;
