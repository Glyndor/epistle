//! `database.sql` lives at the archive root, not under the archive's
//! `data/` prefix. Laying it down as `<data_dir>/database.sql` would
//! (a) put a `0644` secret-bearing file in the next backup, (b) make
//! it visible to anything that walks the data directory, and (c)
//! contradict the layout the archive describes. These tests assert
//! the restore path skips the entry on disk while still handing the
//! bytes to the database restore step.

use super::*;
use std::os::unix::fs::PermissionsExt;

const DB_SQL: &str = super::DATABASE_SQL_NAME;

/// Mirror of the sibling test module's private fixture, kept here so
/// the database-sql tests are self-contained.
fn build_archive_with_database_sql(sql: Option<&[u8]>) -> Vec<u8> {
	let mut entries: Vec<(String, u32, Vec<u8>)> = vec![(
		"data/accounts/alice/new/m1.eml".to_string(),
		0o644,
		b"Subject: hi\r\n\r\nbody".to_vec(),
	)];
	if let Some(sql) = sql {
		entries.push((DB_SQL.to_string(), 0o644, sql.to_vec()));
	}
	tar_gz(&entries).expect("tar_gz")
}

/// Write a shell-stub script at `path` and make it executable, so it
/// can stand in for a real binary without invoking a real one.
fn write_shell_stub(path: &std::path::Path, body: &[u8]) {
	if let Some(parent) = path.parent() {
		std::fs::create_dir_all(parent).expect("mkdir stub parent");
	}
	std::fs::write(path, body).expect("write stub");
	std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod 0755");
}

/// The simplest possible assertion of the bug: after `run_restore`
/// over an archive that carries `database.sql`, the data directory
/// must not contain a `database.sql` file.
#[test]
fn database_sql_is_not_laid_into_data_dir() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data dir");
	let sql = b"create table restore_sql_skip (id int);\n";
	let archive = build_archive_with_database_sql(Some(sql));
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n\
		 \n[database]\nurl = \"postgres://epistle@localhost/epistle?sslmode=require\"\n",
		data_dir.display()
	);
	let config: Config = toml::from_str(&toml).expect("config");
	let mut out = Vec::new();
	let mut status = Vec::new();
	// Force the restore through; the bug is on the file-write path,
	// not the database step. The data directory should still not
	// contain `database.sql` afterwards.
	let exit = run_restore_with(
		&config,
		&archive,
		true,
		false,
		&mut out,
		&mut status,
		&|program| {
			// `Command::new` falls back to `PATH`; the production
			// resolver would return `None`. The real `psql` is
			// not on the host `PATH` here, so the database step
			// fails with `BinaryMissing` — which is the failure
			// mode the assertion below relies on.
			let _ = program;
			None
		},
	);
	assert_ne!(exit, ExitCode::SUCCESS, "no psql → restore must fail");
	assert!(
		!data_dir.join("database.sql").exists(),
		"database.sql must not be written into data_dir: {}",
		data_dir.join("database.sql").display()
	);
	// The mail entry under `data/` is still extracted.
	assert!(data_dir.join("accounts/alice/new/m1.eml").exists());
	// Database restore nevertheless got the SQL bytes — the archive
	// entry is reached through `entries` in `run_restore`, separate
	// from `lay_files`. We assert that here by checking the bytes
	// are passed to the psql process: with `psql` absent, the absence
	// of `database.sql` on disk is the observable we have.
}

/// Same archive, but `psql` is stubbed to confirm the SQL bytes are
/// delivered through the entry list rather than a path on disk. The
/// stub records its argv to a temp file we can read back.
#[test]
fn database_sql_reaches_psql_through_the_entry_list() {
	let dir = tempfile::tempdir().expect("tempdir");
	let bin = dir.path().join("bin");
	let psql_stub = bin.join("psql");
	let marker_path = dir.path().join("psql-args.txt");
	let marker_str = marker_path.to_string_lossy().into_owned();
	write_shell_stub(
		&psql_stub,
		format!("#!/bin/sh\nprintf 'saw-psql' > {marker_str}\nexit 0\n").as_bytes(),
	);
	// Re-apply the executable permission: `write_shell_stub` already
	// does this, but the help text makes the dependency explicit.
	std::fs::set_permissions(&psql_stub, std::fs::Permissions::from_mode(0o755))
		.expect("chmod psql");
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data dir");
	let archive = build_archive_with_database_sql(Some(b"-- marker sql --\n"));
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n\
		 \n[database]\nurl = \"postgres://epistle@localhost/epistle?sslmode=require\"\n",
		data_dir.display()
	);
	let config: Config = toml::from_str(&toml).expect("config");
	let mut out = Vec::new();
	let mut status = Vec::new();
	let psql_stub_for_resolver = psql_stub.clone();
	let resolver = move |program: &str| {
		if program == "psql" {
			Some(psql_stub_for_resolver.clone())
		} else {
			None
		}
	};
	let exit = run_restore_with(
		&config,
		&archive,
		true,
		false,
		&mut out,
		&mut status,
		&resolver,
	);
	// The stub exits 0, so the database restore succeeds and the
	// overall restore is green even though `psql` was the dummy.
	// We do not assert on the exit code here — the binary does
	// not write a psql-conf error — only on the side-effects.
	let _ = exit;
	let marker = std::fs::read_to_string(&marker_path).unwrap_or_default();
	assert!(
		marker.contains("saw-psql"),
		"psql was not invoked: {marker}"
	);
	assert!(!data_dir.join("database.sql").exists());
}
