//! A SIGTERM sent to the process group of a restore while the container load
//! is under way, as the Debian 13 VM sent it in #1331. The restore runs in a
//! child process with a group of its own, so the signal reaches the restore
//! and the `podup` stub it is waiting on, and not this test. The stub commits
//! the pretend load before it signals, the way `psql` in the `db` container
//! went on after `epistle` was gone. After signalling, the stub waits until
//! the restore's stderr carries the line its handler writes, so the restore
//! has recorded the signal before the stub returns and the step that follows
//! is the same on every run.
//!
//! A signal before the load must leave the database and the files untouched,
//! one during the load must let both be restored, and either way nothing
//! staged may be left on the host or in the container, and the process must
//! end by the signal.

use std::fs;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};

use super::staging::{FakeEngine, archive_entries, mail_file, restore_at};

/// Set in the child: the engine's directory of notes, its stub and its
/// compose file, separated by newlines.
const CHILD: &str = "EPISTLE_TEST_SIGNALLED_RESTORE";

/// The restore the parent test signals. Does nothing in an ordinary run.
#[test]
fn signalled_restore_child() {
	let Some(spec) = std::env::var_os(CHILD) else {
		return;
	};
	let spec = spec.into_string().expect("utf-8 paths");
	let mut lines = spec.lines().map(PathBuf::from);
	let (rec, stub, compose) = (
		lines.next().expect("rec"),
		lines.next().expect("stub"),
		lines.next().expect("compose"),
	);
	// SAFETY: getpgrp takes no arguments and cannot fail.
	let group = unsafe { libc::getpgrp() };
	fs::write(rec.join("pgid"), group.to_string()).expect("pgid");
	let code = restore_at(&compose, &stub, &archive_entries());
	std::process::exit(if code == std::process::ExitCode::SUCCESS {
		0
	} else {
		1
	});
}

/// What a restore signalled at `step` left behind.
struct Left {
	status: std::process::ExitStatus,
	database_loaded: bool,
	files_laid: bool,
	container: Vec<String>,
	host: Vec<String>,
}

fn signalled_at(step: &str) -> Left {
	let engine = FakeEngine::new();
	engine.switch_on(&format!("signal-at-{step}"));
	let host_tmp = tempfile::tempdir().expect("host tmp");
	let spec = [&engine.rec, &engine.stub, &engine.compose]
		.map(|path| path.display().to_string())
		.join("\n");
	let stderr = fs::File::create(engine.rec.join("child.stderr")).expect("stderr");
	let status = std::process::Command::new(std::env::current_exe().expect("test binary"))
		.args([
			"--exact",
			"cli::backup::db_dump::tests::signal::signalled_restore_child",
			"--test-threads=1",
		])
		.env(CHILD, spec)
		.env("TMPDIR", host_tmp.path())
		.process_group(0)
		.stdout(std::process::Stdio::null())
		.stderr(stderr)
		.status()
		.expect("run the restore");
	Left {
		status,
		database_loaded: engine.rec.join("psql.sql").exists(),
		files_laid: mail_file(&engine).exists(),
		container: engine.container_tmp(),
		host: staged_on_host(host_tmp.path()),
	}
}

fn staged_on_host(dir: &Path) -> Vec<String> {
	fs::read_dir(dir)
		.expect("host tmp")
		.map(|entry| {
			entry
				.expect("entry")
				.file_name()
				.to_string_lossy()
				.into_owned()
		})
		.filter(|name| name.starts_with("epistle-restore-"))
		.collect()
}

fn assert_whole(step: &str) -> Left {
	let left = signalled_at(step);
	assert_eq!(
		left.status.signal(),
		Some(libc::SIGTERM),
		"the restore must end by the signal it was sent ({:?})",
		left.status
	);
	assert_eq!(
		left.database_loaded, left.files_laid,
		"signal at {step}: database restored {} but files restored {}",
		left.database_loaded, left.files_laid
	);
	assert_eq!(
		left.container,
		Vec::<String>::new(),
		"signal at {step}: staged copy left in the container"
	);
	assert_eq!(
		left.host,
		Vec::<String>::new(),
		"signal at {step}: staged copy left on the host"
	);
	left
}

/// A signal before `psql` starts stops the restore with nothing written.
fn assert_untouched(step: &str) {
	let left = assert_whole(step);
	assert!(
		!left.database_loaded && !left.files_laid,
		"signal at {step}: the load had not started, so nothing may be restored"
	);
}

#[test]
fn a_signal_while_old_copies_are_swept_restores_nothing() {
	assert_untouched("ls");
}

#[test]
fn a_signal_while_the_container_directory_is_made_restores_nothing() {
	assert_untouched("mkdir");
}

#[test]
fn a_signal_while_the_dump_is_copied_in_restores_nothing() {
	assert_untouched("cp");
}

/// Once `psql` has run, the load is not undone, so the restore finishes.
#[test]
fn a_signal_while_the_dump_loads_lets_the_restore_finish() {
	let left = assert_whole("psql");
	assert!(
		left.database_loaded && left.files_laid,
		"the load had started, so both halves must be restored"
	);
}
