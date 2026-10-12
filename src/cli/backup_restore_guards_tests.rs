//! `epistle restore` must refuse to overwrite an existing `data_dir`
//! or run while the mail service is up, unless `--force` is given;
//! `--dry-run` lists what would be written and changes nothing.

use super::*;

/// Build the smallest possible archive fixture: one `data/...`
/// entry, no `database.sql` (so the test does not need a stub
/// `psql`). The function is local because the sibling `*_tests_*`
/// files keep this exact fixture private.
fn build_archive_with_one_entry() -> Vec<u8> {
	let entries: Vec<(String, u32, Vec<u8>)> = vec![(
		"data/accounts/alice/new/m1.eml".to_string(),
		0o644,
		b"Subject: hi\r\n\r\nbody".to_vec(),
	)];
	tar_gz(&entries).expect("tar_gz")
}

fn build_config(data_dir: &std::path::Path) -> Config {
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
		data_dir.display()
	);
	toml::from_str(&toml).expect("config")
}

/// Without `--force`, restore refuses when `data_dir` already has an
/// account store, and the refusal names the file that triggered it
/// plus the recovery hint.
#[test]
fn restore_refuses_non_empty_data_dir_without_force() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data dir");
	// Pre-existing artefact: the same file a previous restore would
	// have produced. Picking one the refusal logic checks first
	// (`accounts.toml`) keeps the test focused on the production path.
	std::fs::write(data_dir.join("accounts.toml"), "[[accounts]]\n").expect("preset");
	let archive = build_archive_with_one_entry();
	let config = build_config(&data_dir);
	let mut out = Vec::new();
	let mut status = Vec::new();
	let exit = run_restore(&config, &archive, false, false, &mut out, &mut status);
	assert_ne!(exit, ExitCode::SUCCESS, "non-empty data_dir must be refused");
	let status_text = String::from_utf8(status).unwrap();
	assert!(
		status_text.contains("refusing to restore"),
		"status must explain: {status_text}"
	);
	assert!(
		status_text.contains("accounts.toml"),
		"status must name the offending file: {status_text}"
	);
	assert!(
		status_text.contains("--force"),
		"status must suggest the recovery: {status_text}"
	);
	// The original file must still be there, untouched.
	let after = std::fs::read_to_string(data_dir.join("accounts.toml")).unwrap();
	assert_eq!(after, "[[accounts]]\n");
	// The archive entry must not have been written either.
	assert!(!data_dir.join("accounts/alice/new/m1.eml").exists());
}

/// `--force` lets the restore proceed over an existing account store.
#[test]
fn restore_force_overwrites_existing_data_dir() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data dir");
	std::fs::write(data_dir.join("accounts.toml"), "[[accounts]]\n").expect("preset");
	let archive = build_archive_with_one_entry();
	let config = build_config(&data_dir);
	let mut out = Vec::new();
	let mut status = Vec::new();
	let exit = run_restore(&config, &archive, true, false, &mut out, &mut status);
	assert_eq!(exit, ExitCode::SUCCESS, "force must let the restore succeed");
	assert!(data_dir.join("accounts/alice/new/m1.eml").exists());
}

/// `--dry-run` lists the entries and writes nothing.
#[test]
fn restore_dry_run_lists_entries_and_writes_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data dir");
	let archive = build_archive_with_one_entry();
	let config = build_config(&data_dir);
	let mut out = Vec::new();
	let mut status = Vec::new();
	let exit = run_restore(&config, &archive, false, true, &mut out, &mut status);
	assert_eq!(exit, ExitCode::SUCCESS, "dry-run must exit 0");
	let out_text = String::from_utf8(out).unwrap();
	assert!(
		out_text.contains("would restore"),
		"dry-run header missing: {out_text}"
	);
	assert!(
		out_text.contains("data/accounts/alice/new/m1.eml"),
		"dry-run must list the entry: {out_text}"
	);
	// The dry-run path promises no writes; verify it.
	assert!(!data_dir.join("accounts/alice/new/m1.eml").exists());
	// The data directory was empty before this test and stays empty
	// (no `accounts/` subdir created).
	assert!(!data_dir.join("accounts").exists());
}

/// With a database in the archive, the dry-run lists `database.sql`
/// as a separate entry (replayed to psql), and never lays it on disk.
#[test]
fn restore_dry_run_with_database_sql_mentions_psql_but_not_data_dir() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data dir");
	let mut entries: Vec<(String, u32, Vec<u8>)> = vec![(
		"data/accounts/alice/new/m1.eml".to_string(),
		0o644,
		b"Subject: hi\r\n\r\nbody".to_vec(),
	)];
	entries.push(("database.sql".to_string(), 0o644, b"create table x (id int);\n".to_vec()));
	let archive = tar_gz(&entries).expect("tar_gz");
	let config = build_config(&data_dir);
	let mut out = Vec::new();
	let mut status = Vec::new();
	let exit = run_restore(&config, &archive, false, true, &mut out, &mut status);
	assert_eq!(exit, ExitCode::SUCCESS);
	let out_text = String::from_utf8(out).unwrap();
	assert!(out_text.contains("database.sql"), "{out_text}");
	assert!(out_text.contains("psql"), "{out_text}");
	assert!(!data_dir.join("database.sql").exists());
}

/// A dry-run over an empty directory is the simplest green path: it
/// does not trigger the refusal even though `data_dir` exists.
#[test]
fn restore_dry_run_empty_target_does_not_refuse() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data dir");
	let archive = build_archive_with_one_entry();
	let config = build_config(&data_dir);
	let mut out = Vec::new();
	let mut status = Vec::new();
	let exit = run_restore(&config, &archive, false, true, &mut out, &mut status);
	assert_eq!(exit, ExitCode::SUCCESS);
	let status_text = String::from_utf8(status).unwrap();
	assert!(
		!status_text.contains("refusing"),
		"empty dir must not be refused: {status_text}"
	);
}
