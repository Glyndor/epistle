//! The container restore against a `podup` stub that models what the VM
//! measured (Debian 13, podup 5.14.0, podman 5.4.2) in a database container
//! that drops every capability: `podup cp` keeps the mode and the numeric owner
//! of the host file, and that owner (uid 103) is neither root nor the database
//! user; the password is read by the database user alone; the database user
//! reads a file only through `o+r`; root cannot change the mode or the owner of
//! a file that is not its own, and can remove entries of a directory it owns.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::a4_tempfile::UmaskGuard;
use super::{BackupError, RestoreHostTemp, leftover_note, load_dump_container_with};

const SQL: &[u8] =
	b"insert into accounts values ('credential-hash');\n-- PostgreSQL database dump complete\n--\n";

/// The pretend container: its file tree, the notes the stub keeps, and the
/// stub itself.
pub(in super::super) struct FakeEngine {
	_root: tempfile::TempDir,
	pub(in super::super) fs: PathBuf,
	pub(in super::super) rec: PathBuf,
	pub(in super::super) stub: PathBuf,
	pub(in super::super) compose: PathBuf,
}

impl FakeEngine {
	pub(in super::super) fn new() -> Self {
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
hit() {{
	[ -f "$REC/signal-at-$1" ] || return 0
	kill -s TERM -- "-$(cat "$REC/pgid")"
	n=0
	until grep -q 'stop signal arrived' "$REC/child.stderr" 2>/dev/null || [ $n -ge 500 ]; do
		sleep 0.01; n=$((n + 1))
	done
}}
for last; do :; done
case " $* " in *' -u root '*) user=root;; *) user=postgres;; esac
case "$*" in
*' cp '*)
	dest="${{5#db:}}"
	[ -d "$(dirname "$FS$dest")" ] || {{ echo "Error: no such directory" >&2; exit 125; }}
	cp "$4" "$FS$dest" || exit 1
	echo 103 > "$FS$dest.owner"
	stat -c %a "$4" > "$FS$dest.mode"
	hit cp; exit 0;;
esac
case "$last" in
"ls -1 /tmp")
	[ -f "$REC/ls-fails" ] && exit 1
	ls -1 "$FS/tmp" | grep -v '\.\(owner\|mode\)$'; hit ls; exit 0;;
"mkdir -m "*)
	d="${{last#mkdir -m * \'}}"; d="${{d%\'}}"
	[ -f "$REC/mkdir-fails" ] && {{ echo "mkdir: cannot create directory: File exists" >&2; exit 1; }}
	mkdir -m 700 "$FS$d" && echo "$user" > "$FS$d.owner" || exit 1
	hit mkdir; exit 0;;
"chmod "*|"chown "*)
	echo "chmod: changing permissions: Operation not permitted" >&2; exit 1;;
"rm -rf "*)
	d="${{last#rm -rf \'}}"; d="${{d%\'}}"
	[ "$user" = root ] || {{ echo "rm: cannot remove: Operation not permitted" >&2; exit 1; }}
	[ -f "$REC/rm-fails" ] && {{ echo "rm: cannot remove: Read-only file system" >&2; exit 1; }}
	rm -rf "$FS$d" "$FS$d.owner"; exit 0;;
*psql*)
	[ "$user" = postgres ] || {{ echo "cat: can't open '/run/secrets/epistle_db_password': Permission denied" >&2; exit 1; }}
	f="${{last#*-f \'}}"; f="${{f%%\'*}}"
	[ -f "$FS$f" ] || {{ echo "psql: no such file" >&2; exit 2; }}
	case "$(cat "$FS$f.mode")" in
	*[4567]) ;;
	*) echo "psql: $f: Permission denied" >&2; exit 2;;
	esac
	cat "$FS$f" > "$REC/psql.sql"
	[ -f "$REC/psql-fails" ] && {{ echo "ERROR: boom" >&2; exit 3; }}
	hit psql; exit 0;;
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

	pub(in super::super) fn switch_on(&self, name: &str) {
		fs::write(self.rec.join(name), "").expect("switch");
	}

	fn restore(&self) -> Result<(), BackupError> {
		let stub = self.stub.clone();
		let resolver = move |program: &str| (program == "podup").then(|| stub.clone());
		crate::cli::backup::tests::helpers::retry_on_text_file_busy(|| {
			load_dump_container_with(&self.compose, SQL, &resolver)
		})
	}

	/// What is left in the pretend container's `/tmp`.
	pub(in super::super) fn container_tmp(&self) -> Vec<String> {
		fs::read_dir(self.fs.join("tmp"))
			.expect("tmp")
			.map(|entry| {
				entry
					.expect("entry")
					.file_name()
					.to_string_lossy()
					.into_owned()
			})
			.filter(|name| !name.ends_with(".owner"))
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
	let calls = engine.calls();
	assert!(
		!calls.contains("chmod 600") && !calls.contains("chown"),
		"{calls}"
	);
	assert!(!calls.contains("chmod"), "{calls}");
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
	assert!(
		message.contains("podup exec -T -u root db rm -rf"),
		"{message}"
	);
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
	let mask = UmaskGuard::new(0o077);
	let temp = RestoreHostTemp::create().expect("temp");
	let dir_mode = fs::metadata(temp.dir()).expect("dir").permissions().mode() & 0o777;
	let file_mode = fs::metadata(temp.path())
		.expect("file")
		.permissions()
		.mode()
		& 0o777;
	drop(mask);
	assert_eq!((dir_mode, file_mode), (0o700, 0o644));
	assert_eq!(temp.path().parent(), Some(temp.dir()));
	assert!(Path::new(temp.dir()).starts_with(std::env::temp_dir()));
}

/// Nothing is removed in the container when its directory was not made: the
/// name was not ours.
#[test]
fn nothing_is_removed_when_the_directory_could_not_be_made() {
	let engine = FakeEngine::new();
	engine.switch_on("mkdir-fails");
	engine.restore().expect_err("mkdir fails");
	assert!(!engine.calls().contains("rm -rf"), "{}", engine.calls());
}

/// The directories an interrupted restore left in the container go at the next
/// restore; one that belongs to a restore still running stays.
#[test]
fn the_next_restore_removes_what_an_interrupted_one_left() {
	let engine = FakeEngine::new();
	let mut child = std::process::Command::new("true").spawn().expect("spawn");
	let dead = child.id();
	child.wait().expect("wait");
	let stale = format!("epistle-restore-{dead}-1-0");
	let live = format!("epistle-restore-{}-1-0", std::process::id());
	for name in [&stale, &live, &"unrelated".to_string()] {
		fs::create_dir(engine.fs.join("tmp").join(name)).expect("dir");
	}
	engine.restore().expect("the restore works");
	assert_eq!(
		{
			let mut left = engine.container_tmp();
			left.sort();
			left
		},
		{
			let mut kept = vec![live, "unrelated".to_string()];
			kept.sort();
			kept
		}
	);
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
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n\n[database]\nurl = \"postgres://epistle@localhost/epistle\"\n",
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
