//! Tests for the `epistle restore` flow and the host-side failure
//! paths of `epistle backup`: the entry point reads a tar.gz from
//! stdin, lays the `data/` entries down under `data_dir`, and replays
//! `database.sql` when the configuration has a `[database]` section.
//! The host-side and the container-side `load_dump` paths are
//! exercised by faking the program resolver rather than mutating the
//! process `PATH` (which would race other parallel tests).

use super::*;
use std::os::unix::fs::PermissionsExt;

/// The path of `database.sql` inside the backup archive. Re-exposed
/// here so the test reads as one block; the production path uses the
/// same constant.
const DB_SQL: &str = super::DATABASE_SQL_NAME;

/// Build a tar.gz archive that contains one `data/...` entry and an
/// optional `database.sql` entry. The helper keeps the tests free of
/// the tar/gzip details so each test reads as a single scenario.
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

/// A resolver that returns the absolute path of a stub for a known
/// set of program names, and falls through to the default for
/// everything else. The test installs a stub in a tempdir and the
/// resolver points the spec at the tempdir path. The default
/// resolver in production never sees a relative path; this test
/// resolver only handles the binaries the test cares about.
///
/// Returns `(name, path)` pairs by `String` + `PathBuf` so the
/// closure owns its data and the resolver can be passed straight
/// into the run-with path. The `stubs` argument is collected into
/// the closure and outlives the returned value, so the test that
/// uses the resolver does not need to keep `stubs` alive.
fn stub_resolver(
	stubs: Vec<(String, std::path::PathBuf)>,
) -> impl Fn(&str) -> Option<std::path::PathBuf> {
	move |program: &str| {
		stubs
			.iter()
			.find(|(name, _)| name == program)
			.map(|(_, path)| path.clone())
	}
}

/// Write a shell-stub script at `path` and make it executable. The
/// body is a `sh` script; the simplest case is `exit 0` or a `printf`
/// of canned stdout.
fn write_shell_stub(path: &std::path::Path, body: &[u8]) {
	if let Some(parent) = path.parent() {
		std::fs::create_dir_all(parent).expect("mkdir stub parent");
	}
	std::fs::write(path, body).expect("write stub");
	std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod 0755");
}

#[test]
fn run_restore_lays_down_data_files_from_archive() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data dir");
	let archive = build_archive_with_database_sql(None);
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
		data_dir.display()
	);
	let config: Config = toml::from_str(&toml).expect("config");
	let mut out = Vec::new();
	assert_eq!(run_restore(&config, &archive, &mut out), ExitCode::SUCCESS);
	let restored = data_dir.join("accounts/alice/new/m1.eml");
	let body = std::fs::read(&restored).expect("read restored");
	assert_eq!(body, b"Subject: hi\r\n\r\nbody");
}

#[test]
fn run_restore_fails_when_archive_carries_database_sql_but_psql_errors() {
	let dir = tempfile::tempdir().expect("tempdir");
	let bin = dir.path().join("bin");
	let psql_stub = bin.join("psql");
	write_shell_stub(
		&psql_stub,
		b"#!/bin/sh\necho 'FATAL: relation \"x\" does not exist' >&2\nexit 1\n",
	);
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data dir");
	let archive = build_archive_with_database_sql(Some(b"create table x (id int);\n"));
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n\
		 \n[database]\nurl = \"postgres://epistle@localhost/epistle\"\n",
		data_dir.display()
	);
	let config: Config = toml::from_str(&toml).expect("config");
	let mut out = Vec::new();
	let resolver = stub_resolver(vec![("psql".to_string(), psql_stub.clone())]);
	let exit = run_restore_with(&config, &archive, &mut out, &resolver);
	assert_ne!(
		exit,
		ExitCode::SUCCESS,
		"psql failed; restore must not be green"
	);
}

#[test]
fn run_restore_fails_when_archive_has_no_database_sql_but_database_is_configured() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data dir");
	let archive = build_archive_with_database_sql(None);
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n\
		 \n[database]\nurl = \"postgres://epistle@localhost/epistle\"\n",
		data_dir.display()
	);
	let config: Config = toml::from_str(&toml).expect("config");
	let mut out = Vec::new();
	assert_ne!(
		run_restore(&config, &archive, &mut out),
		ExitCode::SUCCESS,
		"a configured database with no SQL in the archive is a restore error"
	);
}

#[test]
fn run_restore_fails_on_empty_archive() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data dir");
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
		data_dir.display()
	);
	let config: Config = toml::from_str(&toml).expect("config");
	let mut out = Vec::new();
	assert_ne!(
		run_restore(&config, &[], &mut out),
		ExitCode::SUCCESS,
		"empty bytes are not a valid archive"
	);
}

#[test]
fn backup_restore_round_trip_includes_database_sql() {
	// The simpler of the round-trips: build a tar.gz through the real
	// `tar_gz` path with a `database.sql` entry, then read it back
	// through `read_tar_entries` and confirm the SQL is in there.
	let sql = b"create table foo (id int);\n";
	let archive = build_archive_with_database_sql(Some(sql));
	let entries = helpers::read_tar_entries(&helpers::gunzip(&archive));
	let (name, _, content) = entries
		.iter()
		.find(|(n, _, _)| n == DB_SQL)
		.expect("database.sql in archive");
	assert_eq!(name, DB_SQL);
	assert_eq!(content, sql);
}

#[test]
fn backup_with_database_writes_the_dump_bytes_into_the_archive() {
	// Host path: no compose file, the `pg_dump` resolver returns a
	// stub that prints the SQL. The archive must carry a
	// `database.sql` entry with those bytes.
	let dir = tempfile::tempdir().expect("tempdir");
	let bin = dir.path().join("bin");
	let pg_dump_stub = bin.join("pg_dump");
	write_shell_stub(
		&pg_dump_stub,
		b"#!/bin/sh\nprintf 'CREATE TABLE accounts (id int);\\n'\n",
	);
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data dir");
	std::fs::write(data_dir.join("seed.eml"), b"seed").expect("seed");
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n\
		 \n[database]\nurl = \"postgres://epistle@localhost/epistle\"\n",
		data_dir.display()
	);
	let config: Config = toml::from_str(&toml).expect("config");
	let resolver = stub_resolver(vec![("pg_dump".to_string(), pg_dump_stub.clone())]);
	let mut archive = Vec::new();
	let mut warnings = Vec::new();
	let exit = run_with(&config, &mut archive, &mut warnings, &resolver);
	assert_eq!(
		exit,
		ExitCode::SUCCESS,
		"backup must run green against the stub pg_dump"
	);
	let entries = helpers::read_tar_entries(&helpers::gunzip(&archive));
	let sql_entry = entries
		.iter()
		.find(|(n, _, _)| n == DB_SQL)
		.expect("database.sql entry must be present");
	assert!(sql_entry.2.starts_with(b"CREATE TABLE"));
}

#[test]
fn backup_fails_when_pg_dump_exits_non_zero() {
	let dir = tempfile::tempdir().expect("tempdir");
	let bin = dir.path().join("bin");
	let pg_dump_stub = bin.join("pg_dump");
	write_shell_stub(
		&pg_dump_stub,
		b"#!/bin/sh\necho 'connection refused' >&2\nexit 2\n",
	);
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data dir");
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n\
		 \n[database]\nurl = \"postgres://epistle@localhost/epistle\"\n",
		data_dir.display()
	);
	let config: Config = toml::from_str(&toml).expect("config");
	let resolver = stub_resolver(vec![("pg_dump".to_string(), pg_dump_stub.clone())]);
	let mut archive = Vec::new();
	let mut warnings = Vec::new();
	let exit = run_with(&config, &mut archive, &mut warnings, &resolver);
	assert_ne!(
		exit,
		ExitCode::SUCCESS,
		"a non-zero pg_dump must make `epistle backup` exit non-zero, not silently skip the database"
	);
}

#[test]
fn backup_fails_when_pg_dump_produces_no_output() {
	let dir = tempfile::tempdir().expect("tempdir");
	let bin = dir.path().join("bin");
	let pg_dump_stub = bin.join("pg_dump");
	// Exits 0 but produces nothing. The empty-output branch is the
	// one that catches a connection that dropped mid-stream.
	write_shell_stub(&pg_dump_stub, b"#!/bin/sh\nexit 0\n");
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data dir");
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n\
		 \n[database]\nurl = \"postgres://epistle@localhost/epistle\"\n",
		data_dir.display()
	);
	let config: Config = toml::from_str(&toml).expect("config");
	let resolver = stub_resolver(vec![("pg_dump".to_string(), pg_dump_stub.clone())]);
	let mut archive = Vec::new();
	let mut warnings = Vec::new();
	let exit = run_with(&config, &mut archive, &mut warnings, &resolver);
	assert_ne!(
		exit,
		ExitCode::SUCCESS,
		"empty pg_dump output must make `epistle backup` exit non-zero"
	);
}

#[test]
fn backup_fails_when_pg_dump_binary_is_missing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data dir");
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n\
		 \n[database]\nurl = \"postgres://epistle@localhost/epistle\"\n",
		data_dir.display()
	);
	let config: Config = toml::from_str(&toml).expect("config");
	// A resolver that always returns `None` (the default behaviour)
	// is the only way to be sure `Command::new` looks up `pg_dump` on
	// the host `PATH` exactly the way production does. A test that
	// wanted to "fake" the missing case would stub `pg_dump` to
	// fail; this test does the opposite and relies on the host
	// having no `pg_dump` to look up, which is the real-world
	// failure mode the issue describes.
	//
	// We can't actually delete the system `pg_dump` from `PATH` for
	// this test, so we exercise the variant directly: `BinaryMissing`
	// surfaces from `run_command_capturing_stdout_with` when the
	// resolved path does not exist. The resolver below returns a
	// non-existent path.
	let bogus = dir.path().join("no-such-pg_dump");
	let resolver = move |program: &str| {
		if program == "pg_dump" {
			Some(bogus.clone())
		} else {
			None
		}
	};
	let mut archive = Vec::new();
	let mut warnings = Vec::new();
	let exit = run_with(&config, &mut archive, &mut warnings, &resolver);
	assert_ne!(
		exit,
		ExitCode::SUCCESS,
		"a missing pg_dump must make `epistle backup` exit non-zero"
	);
}
