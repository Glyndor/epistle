//! The container restore against a `podup` stub that behaves like the
//! engine measured on Debian 13 (podup 5.14.0, podman 5.4.2): `podup cp`
//! leaves the copy owned by the host user, so the container user cannot
//! `chmod` it or `rm` it by name in the sticky `/tmp`, while it can still
//! read it and can remove anything inside a directory it owns.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::tests_a4_tempfile::UmaskGuard;
use super::{BackupError, RestoreHostTemp, leftover_note, load_dump_container_with};

const SQL: &[u8] = b"insert into accounts values ('credential-hash');\n";

/// The pretend container: its file tree, the notes the stub keeps, and the
/// stub itself.
struct FakeEngine {
	_root: tempfile::TempDir,
	fs: PathBuf,
	rec: PathBuf,
	stub: PathBuf,
	compose: PathBuf,
}

impl FakeEngine {
	fn new() -> Self {
		let root = tempfile::tempdir().expect("root");
		let fs_dir = root.path().join("fs");
		let rec = root.path().join("rec");
		fs::create_dir_all(fs_dir.join("tmp")).expect("fake /tmp");
		fs::create_dir_all(&rec).expect("rec");
		let compose_dir = root.path().join("data/compose");
		fs::create_dir_all(&compose_dir).expect("compose dir");
		let compose = compose_dir.join("compose.yaml");
		fs::write(&compose, "{}").expect("compose");
		let script = format!(
			r#"#!/bin/sh
FS='{fs}'; REC='{rec}'
printf '%s\n' "$*" >> "$REC/calls.log"
for last; do :; done
case "$*" in
*' cp '*)
	dest="${{5#db:}}"
	[ -d "$(dirname "$FS$dest")" ] || {{ echo "Error: no such directory" >&2; exit 125; }}
	cp "$4" "$FS$dest" && : > "$FS$dest.foreign"
	exit 0;;
esac
case "$last" in
*chmod*|*chown*)
	echo "chmod: changing permissions of file: Operation not permitted" >&2; exit 1;;
"mkdir -m 700 "*)
	d="${{last#mkdir -m 700 \'}}"; d="${{d%\'}}"
	mkdir -m 700 "$FS$d"; exit $?;;
"rm -f "*)
	echo "rm: cannot remove: Operation not permitted" >&2; exit 1;;
"rm -rf "*)
	[ -f "$REC/rm-fails" ] && {{ echo "rm: cannot remove: Read-only file system" >&2; exit 1; }}
	d="${{last#rm -rf \'}}"; d="${{d%\'}}"
	rm -rf "$FS$d" "$FS$d.foreign"; exit 0;;
*psql*)
	f="${{last#*-f \'}}"; f="${{f%%\'*}}"
	[ -f "$FS$f" ] || {{ echo "psql: no such file" >&2; exit 2; }}
	cat "$FS$f" > "$REC/psql.sql"
	[ -f "$REC/psql-fails" ] && {{ echo "ERROR: boom" >&2; exit 3; }}
	exit 0;;
esac
exit 0
"#,
			fs = fs_dir.display(),
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
			fs: fs_dir,
			rec,
			stub,
			compose,
		}
	}

	fn switch_on(&self, name: &str) {
		fs::write(self.rec.join(name), "").expect("switch");
	}

	fn restore(&self) -> Result<(), BackupError> {
		let stub = self.stub.clone();
		let resolver = move |program: &str| (program == "podup").then(|| stub.clone());
		crate::cli::backup::helpers::retry_on_text_file_busy(|| {
			load_dump_container_with(&self.compose, SQL, &resolver)
		})
	}

	/// What is left in the pretend container's `/tmp`.
	fn container_tmp(&self) -> Vec<String> {
		fs::read_dir(self.fs.join("tmp"))
			.expect("tmp")
			.map(|entry| {
				entry
					.expect("entry")
					.file_name()
					.to_string_lossy()
					.into_owned()
			})
			.collect()
	}

	/// The host path the copy step was given.
	fn staged_host_file(&self) -> PathBuf {
		let calls = fs::read_to_string(self.rec.join("calls.log")).expect("calls");
		let cp = calls
			.lines()
			.find(|l| l.contains(" cp "))
			.expect("a cp call");
		PathBuf::from(cp.split_whitespace().nth(4).expect("cp source"))
	}

	fn calls(&self) -> String {
		fs::read_to_string(self.rec.join("calls.log")).unwrap_or_default()
	}
}

/// The measured failure: the copy is not the container user's, so a `chmod`
/// is refused. The restore must load the dump anyway, and leave nothing in the
/// container or on the host.
#[test]
fn restore_loads_a_copy_owned_by_someone_else_and_leaves_nothing() {
	let engine = FakeEngine::new();
	engine.restore().expect("the restore must work");
	assert_eq!(
		fs::read(engine.rec.join("psql.sql")).expect("psql ran"),
		SQL
	);
	assert!(!engine.calls().contains("chmod"), "{}", engine.calls());
	assert_eq!(engine.container_tmp(), Vec::<String>::new());
	assert!(!engine.staged_host_file().parent().unwrap().exists());
}

/// A replay that fails still removes the copy in the container and on the host.
#[test]
fn a_failed_replay_leaves_nothing_in_the_container_or_on_the_host() {
	let engine = FakeEngine::new();
	engine.switch_on("psql-fails");
	let error = engine.restore().expect_err("psql fails");
	assert!(error.to_string().contains("ERROR: boom"), "{error}");
	assert_eq!(engine.container_tmp(), Vec::<String>::new());
	assert!(!engine.staged_host_file().parent().unwrap().exists());
}

/// The dump survived in the container: a replay that worked still succeeds,
/// since the database is loaded, and the leftover is reported as a warning.
#[test]
fn a_removal_that_fails_after_a_good_replay_does_not_fail_the_restore() {
	let engine = FakeEngine::new();
	engine.switch_on("rm-fails");
	engine.restore().expect("the database was loaded");
	assert_eq!(engine.container_tmp().len(), 1, "the copy is really there");
}

/// When the replay and the removal both fail, the error names what was left
/// and where, and how to remove it.
#[test]
fn a_failed_replay_and_a_failed_removal_say_what_was_left_and_where() {
	let engine = FakeEngine::new();
	engine.switch_on("psql-fails");
	engine.switch_on("rm-fails");
	let message = engine.restore().expect_err("psql fails").to_string();
	assert!(message.contains("ERROR: boom"), "{message}");
	assert!(message.contains("/tmp/epistle-restore-"), "{message}");
	assert!(message.contains("in the db container"), "{message}");
	assert!(message.contains("podup exec -T db rm -rf"), "{message}");
	assert!(message.contains("credential hashes"), "{message}");
}

#[test]
fn leftover_note_is_silent_when_everything_was_removed() {
	assert_eq!(leftover_note(Ok(()), "/tmp/x", Ok(())), None);
}

#[test]
fn leftover_note_names_the_host_path_too() {
	let note = leftover_note(
		Ok(()),
		"/tmp/x",
		Err("/var/tmp/epistle-restore-1/restore.sql on the host: busy".to_string()),
	)
	.expect("a note");
	assert!(note.contains("/var/tmp/epistle-restore-1/restore.sql on the host"));
	assert!(!note.contains("db container"), "{note}");
}

/// The host copy is made inside a directory that only its owner can enter,
/// whatever the umask.
#[test]
fn the_host_copy_sits_in_a_private_directory() {
	let mask = UmaskGuard::new(0o000);
	let temp = RestoreHostTemp::create().expect("temp");
	let dir_mode = fs::metadata(temp.dir()).expect("dir").permissions().mode() & 0o777;
	let file_mode = fs::metadata(temp.path())
		.expect("file")
		.permissions()
		.mode()
		& 0o777;
	drop(mask);
	assert_eq!((dir_mode, file_mode), (0o700, 0o600));
	assert_eq!(temp.path().parent(), Some(temp.dir()));
	assert!(Path::new(temp.dir()).starts_with(std::env::temp_dir()));
}

/// A whole restore through the stub: `data_dir` is the one the stub's
/// compose file sits in.
fn restore_all(engine: &FakeEngine, entries: &[(String, u32, Vec<u8>)]) -> std::process::ExitCode {
	use crate::config::Config;
	let data_dir = engine.compose.parent().unwrap().parent().unwrap();
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n\n[database]\nurl = \"postgres://epistle@localhost/epistle\"\n",
		data_dir.display()
	);
	let config: Config = toml::from_str(&toml).expect("config");
	let archive = crate::cli::backup::tar_gz(entries).expect("archive");
	let stub = engine.stub.clone();
	let resolver = move |program: &str| (program == "podup").then(|| stub.clone());
	super::super::run_restore_with(
		&config,
		&archive,
		true,
		false,
		&mut Vec::new(),
		&mut Vec::new(),
		&resolver,
	)
}

fn archive_entries() -> Vec<(String, u32, Vec<u8>)> {
	vec![
		(
			"data/accounts/alice/new/m1.eml".to_string(),
			0o644,
			b"hi".to_vec(),
		),
		("database.sql".to_string(), 0o644, SQL.to_vec()),
	]
}

fn mail_file(engine: &FakeEngine) -> PathBuf {
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
	assert_eq!(fs::read(engine.rec.join("psql.sql")).expect("psql"), SQL);
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
