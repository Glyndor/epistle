//! The container restore against a `podup` stub that stands where
//! `podup exec -T db sh -c <script>` would: it reads the SQL on its standard
//! input the way `psql -f -` does, keeps what it read, and prints the command
//! tags `psql` prints. The switches make it fail, stop reading early, or print
//! no `COMMIT`.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::{BackupError, load_dump_container_with};

const SQL: &[u8] =
	b"insert into accounts values ('credential-hash');\n-- PostgreSQL database dump complete\n--\n";

/// The pretend container: the notes the stub keeps, and the stub itself.
pub(in super::super) struct FakeEngine {
	_root: tempfile::TempDir,
	pub(in super::super) rec: PathBuf,
	pub(in super::super) stub: PathBuf,
	pub(in super::super) compose: PathBuf,
}

impl FakeEngine {
	pub(in super::super) fn new() -> Self {
		let root = tempfile::tempdir().expect("root");
		let rec = root.path().join("rec");
		fs::create_dir_all(&rec).expect("rec");
		let compose_dir = root.path().join("data/compose");
		fs::create_dir_all(&compose_dir).expect("compose dir");
		let compose = compose_dir.join("compose.yaml");
		fs::write(&compose, "{}").expect("compose");
		let script = format!(
			r#"#!/bin/sh
REC='{rec}'
printf '%s\n' "$*" >> "$REC/calls.log"
for last; do :; done
case "$last" in
*psql*)
	if [ -f "$REC/stops-reading" ]; then
		head -c 10 > "$REC/psql.sql"
		echo BEGIN
		exit 0
	fi
	cat > "$REC/psql.sql"
	[ -f "$REC/psql-fails" ] && {{ echo "ERROR: boom" >&2; exit 3; }}
	echo BEGIN
	[ -f "$REC/no-commit" ] || echo COMMIT
	[ -f "$REC/fails-after-commit" ] && {{ echo "connection reset" >&2; exit 1; }}
	[ -f "$REC/signal-at-psql" ] && {{
		kill -s TERM -- "-$(cat "$REC/pgid")"
		n=0
		until grep -q 'stop signal arrived' "$REC/child.stderr" 2>/dev/null || [ $n -ge 500 ]; do
			sleep 0.01; n=$((n + 1))
		done
	}}
	exit 0;;
esac
exit 0
"#,
			rec = rec.display(),
		);
		let stub = root.path().join("podup");
		let staged = root.path().join("podup.staged");
		fs::write(&staged, script).expect("stub");
		fs::set_permissions(&staged, fs::Permissions::from_mode(0o700)).expect("chmod");
		fs::rename(&staged, &stub).expect("publish");
		// A first run now, so a later spawn does not meet the kernel's
		// `ETXTBSY` on a stub another test thread was still writing.
		let _ = std::process::Command::new(&stub).arg("warm-up").status();
		let _ = fs::remove_file(rec.join("calls.log"));
		Self {
			_root: root,
			rec,
			stub,
			compose,
		}
	}

	pub(in super::super) fn switch_on(&self, name: &str) {
		fs::write(self.rec.join(name), "").expect("switch");
	}

	fn restore_sql(&self, sql: &[u8]) -> Result<(), BackupError> {
		let stub = self.stub.clone();
		let resolver = move |program: &str| (program == "podup").then(|| stub.clone());
		crate::cli::backup::tests::helpers::retry_on_text_file_busy(|| {
			load_dump_container_with(&self.compose, sql, &resolver)
		})
	}

	fn restore(&self) -> Result<(), BackupError> {
		self.restore_sql(SQL)
	}

	/// What the stub read on its standard input.
	fn read_by_psql(&self) -> Vec<u8> {
		fs::read(self.rec.join("psql.sql")).unwrap_or_default()
	}

	fn calls(&self) -> String {
		fs::read_to_string(self.rec.join("calls.log")).unwrap_or_default()
	}
}

/// The SQL reaches `psql` on standard input, inside the transaction the
/// stream carries, and nothing is copied anywhere.
#[test]
fn the_dump_reaches_psql_on_stdin_inside_an_explicit_transaction() {
	let engine = FakeEngine::new();
	engine.restore().expect("the restore loads");
	let mut expected = b"BEGIN;\n".to_vec();
	expected.extend_from_slice(SQL);
	expected.extend_from_slice(b"\nCOMMIT;\n");
	assert_eq!(engine.read_by_psql(), expected);
	let calls = engine.calls();
	assert_eq!(calls.lines().count(), 1, "one podup call, got: {calls}");
	assert!(!calls.contains(" cp "), "nothing is copied: {calls}");
	assert!(calls.contains("psql") && calls.contains("-f -"), "{calls}");
}

/// A dump much larger than a pipe buffer passes whole: the stub reads while
/// the restore writes, so nothing waits on the other.
#[test]
fn a_dump_larger_than_the_pipe_buffer_arrives_whole() {
	let engine = FakeEngine::new();
	let mut sql = b"insert into t values ('x');\n".repeat(200_000);
	sql.extend_from_slice(b"-- PostgreSQL database dump complete\n");
	engine.restore_sql(&sql).expect("loads");
	assert_eq!(engine.read_by_psql().len(), sql.len() + 7 + 9);
}

/// `psql` exiting with an error is the restore's error, with the status.
#[test]
fn a_failing_statement_fails_the_restore_with_psql_status() {
	let engine = FakeEngine::new();
	engine.switch_on("psql-fails");
	match engine.restore() {
		Err(BackupError::CommandFailed { stderr, code }) => {
			assert_eq!(code, Some(3));
			assert!(stderr.contains("boom"), "{stderr}");
		}
		other => panic!("a failing psql must fail the restore: {other:?}"),
	}
}

/// The exec failing after `psql` printed `COMMIT` is not "rolled back": the
/// database has the dump, and the error says so.
#[test]
fn an_exec_that_fails_after_the_commit_says_the_dump_is_in() {
	let engine = FakeEngine::new();
	engine.switch_on("fails-after-commit");
	match engine.restore() {
		Err(BackupError::FailedAfterCommit { stderr }) => {
			assert!(stderr.contains("connection reset"), "{stderr}");
		}
		other => panic!("a failure after the commit must say so: {other:?}"),
	}
}

/// An input that stopped early is rolled back by the server and `psql` exits
/// 0 with no `COMMIT` tag. That is not a restore.
#[test]
fn an_input_that_stopped_early_is_not_a_restore() {
	let engine = FakeEngine::new();
	engine.switch_on("stops-reading");
	assert!(matches!(engine.restore(), Err(BackupError::NotCommitted)));
}

/// `psql` exiting 0 without the commit tag is refused even when it read
/// everything.
#[test]
fn a_run_that_prints_no_commit_tag_is_refused() {
	let engine = FakeEngine::new();
	engine.switch_on("no-commit");
	assert!(matches!(engine.restore(), Err(BackupError::NotCommitted)));
}

/// No `podup` on the path: the restore says which binary is missing.
#[test]
fn a_missing_podup_is_named() {
	let engine = FakeEngine::new();
	let resolver = |_: &str| Some(PathBuf::from("/nonexistent/podup"));
	match load_dump_container_with(&engine.compose, SQL, &resolver) {
		Err(BackupError::BinaryMissing(name)) => assert_eq!(name, "podup"),
		other => panic!("a missing podup must be named: {other:?}"),
	}
}

/// A compose file that disappeared stops the restore before podup runs.
#[test]
fn a_compose_file_that_is_gone_stops_the_restore() {
	let engine = FakeEngine::new();
	fs::remove_file(&engine.compose).expect("remove");
	assert!(matches!(
		engine.restore(),
		Err(BackupError::ComposeFileMissing(_))
	));
	assert!(engine.calls().is_empty());
}

#[test]
fn a_psql_exit_is_a_rollback_and_a_lost_exec_is_not_known() {
	let data = Path::new("/var/lib/mail");
	let exit = BackupError::CommandFailed {
		stderr: String::new(),
		code: Some(3),
	};
	assert!(super::super::super::load_failure_state(&exit, data).contains("rolled the dump back"));
	let lost = BackupError::CommandFailed {
		stderr: String::new(),
		code: None,
	};
	let said = super::super::super::load_failure_state(&lost, data);
	assert!(said.contains("not known"), "{said}");
	assert!(!said.contains("rolled"), "{said}");
}

/// A whole restore through the stub: `data_dir` is the one the stub's
/// compose file sits in.
fn restore_all(engine: &FakeEngine, entries: &[(String, u32, Vec<u8>)]) -> std::process::ExitCode {
	restore_at(&engine.compose, &engine.stub, entries)
}

/// [`restore_all`] from the paths of an engine another process made.
pub(in super::super) fn restore_at(
	compose: &Path,
	stub: &Path,
	entries: &[(String, u32, Vec<u8>)],
) -> std::process::ExitCode {
	use crate::config::Config;
	let data_dir = compose.parent().unwrap().parent().unwrap();
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n\n[database]\nurl = \"postgres://epistle@%2Frun%2Fpostgresql/epistle\"\n",
		data_dir.display()
	);
	let config: Config = toml::from_str(&toml).expect("config");
	let archive = crate::cli::backup::tar_gz(entries).expect("archive");
	let stub = stub.to_path_buf();
	let resolver = move |program: &str| (program == "podup").then(|| stub.clone());
	super::super::super::run_restore_with(
		&config,
		&archive,
		true,
		false,
		&mut Vec::new(),
		&mut Vec::new(),
		&resolver,
	)
}

pub(in super::super) fn archive_entries() -> Vec<(String, u32, Vec<u8>)> {
	vec![
		(
			"data/accounts/alice/new/m1.eml".to_string(),
			0o644,
			b"hi".to_vec(),
		),
		("database.sql".to_string(), 0o644, SQL.to_vec()),
	]
}

pub(in super::super) fn mail_file(engine: &FakeEngine) -> PathBuf {
	engine
		.compose
		.parent()
		.unwrap()
		.parent()
		.unwrap()
		.join("accounts/alice/new/m1.eml")
}

/// A database that cannot be loaded leaves the mail files as they were: the
/// restore used to lay the files first and stop on the database, leaving
/// both halves out of step.
#[test]
fn a_database_that_cannot_load_leaves_no_restored_files() {
	let engine = FakeEngine::new();
	engine.switch_on("psql-fails");
	assert_ne!(
		restore_all(&engine, &archive_entries()),
		std::process::ExitCode::SUCCESS
	);
	assert!(
		!mail_file(&engine).exists(),
		"files restored without a database"
	);
}

/// The same archive restores both halves when the database loads.
#[test]
fn a_restore_that_works_lays_the_files_and_loads_the_database() {
	let engine = FakeEngine::new();
	assert_eq!(
		restore_all(&engine, &archive_entries()),
		std::process::ExitCode::SUCCESS
	);
	assert_eq!(fs::read(mail_file(&engine)).expect("file"), b"hi");
	assert_eq!(engine.read_by_psql(), super::transaction(SQL));
}

/// Files that cannot be laid down are found before the database is touched.
#[test]
fn files_that_cannot_be_laid_down_stop_the_restore_before_the_database() {
	let engine = FakeEngine::new();
	let data_dir = engine.compose.parent().unwrap().parent().unwrap();
	let elsewhere = tempfile::tempdir().expect("elsewhere");
	std::os::unix::fs::symlink(elsewhere.path(), data_dir.join("accounts")).expect("link");
	assert_ne!(
		restore_all(&engine, &archive_entries()),
		std::process::ExitCode::SUCCESS
	);
	assert!(
		!engine.rec.join("psql.sql").exists(),
		"the database was loaded"
	);
	assert!(!engine.calls().contains("psql"), "{}", engine.calls());
}

/// A dump cut short is refused before anything is touched.
#[test]
fn a_dump_without_its_closing_marker_is_refused_before_anything_is_touched() {
	let engine = FakeEngine::new();
	let entries = vec![
		(
			"data/accounts/alice/new/m1.eml".to_string(),
			0o644,
			b"hi".to_vec(),
		),
		(
			"database.sql".to_string(),
			0o644,
			b"insert into t values (1);\n".to_vec(),
		),
	];
	assert_ne!(
		restore_all(&engine, &entries),
		std::process::ExitCode::SUCCESS
	);
	assert!(!mail_file(&engine).exists());
	assert!(!engine.calls().contains("psql"), "{}", engine.calls());
}
