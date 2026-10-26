//! The sweep of the copies a dead service edit left behind, and the recovery
//! copy a failed rollback hands to the operator.

use super::*;

use std::path::Path;

/// Backdate a copy so the sweep takes it as an orphan.
fn age(path: &Path, by: Duration) {
	let when = SystemTime::now() - by;
	fs::File::options()
		.write(true)
		.open(path)
		.unwrap()
		.set_times(fs::FileTimes::new().set_modified(when))
		.unwrap();
}

/// A file of our own shape in `dir`, aged by `by`.
fn copy(dir: &Path, staged: bool, by: Duration) -> std::path::PathBuf {
	let path = if staged {
		staged_path(dir)
	} else {
		recovery_path(dir)
	};
	fs::write(&path, b"copy of a config").unwrap();
	age(&path, by);
	path
}

/// A command killed between its two renames leaves its staged copies behind.
/// The next command under the lock sweeps them, and only them: the operator's
/// own files and the copy of a command still running stay.
#[test]
fn a_sweep_takes_the_staged_copies_of_a_dead_command_and_nothing_else() {
	let dir = tempfile::tempdir().unwrap();
	let old = copy(dir.path(), true, ORPHAN_AGE + Duration::from_secs(60));
	let young = copy(dir.path(), true, Duration::from_secs(60));
	let foreign = dir.path().join("mail.toml");
	fs::write(&foreign, b"copy of a config").unwrap();
	assert_eq!(sweep_orphans(dir.path()), vec![old.clone()]);
	assert!(!old.exists());
	assert!(
		young.is_file(),
		"a copy younger than an hour belongs to a command that still runs"
	);
	assert_eq!(fs::read(&foreign).unwrap(), b"copy of a config");
	assert!(
		sweep_orphans(&dir.path().join("absent")).is_empty(),
		"a directory that is not there has nothing to sweep"
	);
}

/// The recovery copy is the only original left of a file a rollback could not
/// put back, and the error names it. A sweep an hour later must not take the
/// file the operator is about to use; a week later it may.
#[test]
fn a_recovery_copy_survives_the_sweep_that_takes_a_staged_copy() {
	let dir = tempfile::tempdir().unwrap();
	let recovery = copy(dir.path(), false, ORPHAN_AGE + Duration::from_secs(60));
	let staged = copy(dir.path(), true, ORPHAN_AGE + Duration::from_secs(60));
	assert_eq!(
		sweep_orphans(dir.path()),
		vec![staged],
		"only the staged copy is debris"
	);
	assert!(
		recovery.is_file(),
		"the copy the rollback error named must outlive the staged one"
	);
	assert_eq!(fs::read(&recovery).unwrap(), b"copy of a config");
	age(&recovery, RECOVERY_AGE + Duration::from_secs(60));
	assert_eq!(
		sweep_orphans(dir.path()),
		vec![recovery.clone()],
		"a recovery copy is kept for a week and then goes with the rest"
	);
	assert!(!recovery.exists());
}

/// The name of a recovery copy has to be one the sweep does not take, and a
/// file with any other name is the operator's.
#[test]
fn a_name_tells_a_recovery_copy_from_anything_else() {
	let recovery = recovery_path(Path::new("/tmp"));
	assert!(is_recovery(
		&recovery.file_name().unwrap().to_string_lossy()
	));
	for name in [
		staged_path(Path::new("/tmp")).display().to_string(),
		format!(".service-recovery.{}.tmp", uuid::Uuid::now_v7()),
		"mail.toml".to_string(),
		format!(".service-{}.tmp", uuid::Uuid::now_v7()),
	] {
		assert!(!is_recovery(&name), "{name}");
	}
}

/// A file of the operator's that shares the prefix and the suffix of our
/// copies is not one of them. The two names below are what a hand-written
/// backup or a note in the configuration directory looks like, and both are
/// older than any age the sweep works at.
#[test]
fn a_file_that_only_shares_the_prefix_and_the_suffix_survives_the_sweep() {
	let dir = tempfile::tempdir().unwrap();
	let mut operator = Vec::new();
	for name in [".service.notes.tmp", ".service-recovery.mine.bak"] {
		let path = dir.path().join(name);
		fs::write(&path, b"operator file").unwrap();
		age(&path, RECOVERY_AGE + ORPHAN_AGE + Duration::from_secs(60));
		operator.push(path);
	}
	assert!(
		sweep_orphans(dir.path()).is_empty(),
		"only the names our writers build are debris"
	);
	for path in &operator {
		assert_eq!(fs::read(path).unwrap(), b"operator file");
	}
}
