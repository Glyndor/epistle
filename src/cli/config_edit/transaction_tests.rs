//! The staged transaction over a pair of service files: what it restores,
//! and what it leaves behind when a rollback can not put a file back.

use super::*;

use std::time::{Duration, SystemTime};

/// Backdate a copy so the sweep reads it as old.
fn age(path: &Path, by: Duration) {
	let when = SystemTime::now() - by;
	fs::File::options()
		.write(true)
		.open(path)
		.unwrap()
		.set_times(fs::FileTimes::new().set_modified(when))
		.unwrap();
}

#[test]
fn a_second_replacement_failure_restores_the_first_file_and_permissions() {
	let dir = tempfile::tempdir().unwrap();
	let a = dir.path().join("mail.toml");
	let b = dir.path().join("compose.yaml");
	crate::storage::write_secret(&a, b"original config").unwrap();
	crate::storage::write_secret(&b, b"original compose").unwrap();
	let before = fs::metadata(&a).unwrap();
	let mut first =
		Some(Replacement::prepare(&a, b"original config", b"new config", None).unwrap());
	let mut second =
		Some(Replacement::prepare(&b, b"original compose", b"new compose", None).unwrap());
	// Losing the second staged candidate forces a real rename failure
	// after the first replacement has completed.
	fs::remove_file(&second.as_ref().unwrap().candidate.0).unwrap();
	assert!(apply_pair(&mut first, &mut second).is_err());
	assert_eq!(fs::read(&a).unwrap(), b"original config");
	assert_eq!(fs::read(&b).unwrap(), b"original compose");
	assert!(same_permissions(&before, &fs::metadata(&a).unwrap()));
}

#[test]
fn an_uncoordinated_compose_edit_is_preserved_and_the_config_is_restored() {
	let dir = tempfile::tempdir().unwrap();
	let a = dir.path().join("mail.toml");
	let b = dir.path().join("compose.yaml");
	crate::storage::write_secret(&a, b"config before").unwrap();
	crate::storage::write_secret(&b, b"compose before").unwrap();
	let mut first =
		Some(Replacement::prepare(&a, b"config before", b"config after", None).unwrap());
	let mut second =
		Some(Replacement::prepare(&b, b"compose before", b"compose after", None).unwrap());
	crate::storage::write_secret(&b, b"operator update").unwrap();
	assert!(apply_pair(&mut first, &mut second).is_err());
	assert_eq!(fs::read(&a).unwrap(), b"config before");
	assert_eq!(fs::read(&b).unwrap(), b"operator update");
}

#[test]
fn a_failed_rollback_retains_a_durable_recovery_copy() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("mail.toml");
	crate::storage::write_secret(&path, b"config before").unwrap();
	let mut replacement =
		Replacement::prepare(&path, b"config before", b"config after", None).unwrap();
	replacement.apply().unwrap();
	fs::remove_file(&path).unwrap();
	fs::create_dir(&path).unwrap();
	let error = replacement.restore().unwrap_err();
	let copy = replacement.backup.0.clone();
	assert!(
		is_recovery(&copy.file_name().unwrap().to_string_lossy()),
		"the copy is named apart from the staged ones: {copy:?}"
	);
	assert!(error.contains(&copy.display().to_string()), "{error}");
	drop(replacement);
	assert!(
		copy.is_file(),
		"failed rollback must retain its recovery copy"
	);
	assert_eq!(fs::read(&copy).unwrap(), b"config before");
}

/// The rollback failed and nothing could rename anything afterwards either, so
/// the copy the error names has to carry the name it was written with. A copy
/// written under the staged name is one the sweep takes after an hour, and the
/// operator would be told to put back a file the next command deletes. Here
/// the directory itself is gone, which refuses the staging of the restore and
/// any rename out of it alike.
#[test]
fn a_rollback_whose_directory_is_gone_still_names_a_copy_the_sweep_keeps() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("mail.toml");
	crate::storage::write_secret(&path, b"config before").unwrap();
	let mut replacement =
		Replacement::prepare(&path, b"config before", b"config after", None).unwrap();
	replacement.apply().unwrap();
	let moved = dir.path().with_extension("gone");
	fs::rename(dir.path(), &moved).unwrap();
	let error = replacement.restore().unwrap_err();
	let named = replacement.backup.0.clone();
	assert!(
		is_recovery(&named.file_name().unwrap().to_string_lossy()),
		"the copy is named apart from the staged ones: {named:?}"
	);
	assert!(error.contains(&named.display().to_string()), "{error}");
	drop(replacement);
	let copy = moved.join(named.file_name().unwrap());
	assert_eq!(fs::read(&copy).unwrap(), b"config before");
	age(&copy, Duration::from_secs(2 * 3600));
	assert!(
		super::super::sweep_orphans(&moved).is_empty(),
		"an hour later the copy the error named must still be there"
	);
	age(&copy, Duration::from_secs(8 * 24 * 3600));
	assert_eq!(
		super::super::sweep_orphans(&moved),
		vec![copy.clone()],
		"a week later it goes with the rest"
	);
}

/// Both renames succeeded, so the backup of the original has no reader left.
/// Leaving it behind would cost a week-long copy of every edited file.
#[test]
fn a_finished_edit_leaves_no_copy_of_the_original_behind() {
	let dir = tempfile::tempdir().unwrap();
	let a = dir.path().join("mail.toml");
	let b = dir.path().join("compose.yaml");
	crate::storage::write_secret(&a, b"original config").unwrap();
	crate::storage::write_secret(&b, b"original compose").unwrap();
	let mut first =
		Some(Replacement::prepare(&a, b"original config", b"new config", None).unwrap());
	let mut second =
		Some(Replacement::prepare(&b, b"original compose", b"new compose", None).unwrap());
	assert!(apply_pair(&mut first, &mut second).is_ok());
	assert_eq!(fs::read(&a).unwrap(), b"new config");
	assert_eq!(fs::read(&b).unwrap(), b"new compose");
	drop(first);
	drop(second);
	assert_eq!(
		fs::read_dir(dir.path()).unwrap().count(),
		2,
		"the two files and nothing else"
	);
}

#[test]
fn simultaneous_rollback_failures_name_both_recovery_copies() {
	let dir = tempfile::tempdir().unwrap();
	let a = dir.path().join("mail.toml");
	let b = dir.path().join("compose.yaml");
	crate::storage::write_secret(&a, b"config before").unwrap();
	crate::storage::write_secret(&b, b"compose before").unwrap();
	let mut first =
		Some(Replacement::prepare(&a, b"config before", b"config after", None).unwrap());
	let mut second =
		Some(Replacement::prepare(&b, b"compose before", b"compose after", None).unwrap());
	first.as_mut().unwrap().apply().unwrap();
	second.as_mut().unwrap().apply().unwrap();
	for path in [&a, &b] {
		fs::remove_file(path).unwrap();
		fs::create_dir(path).unwrap();
	}
	let error = apply_pair(&mut first, &mut second).unwrap_err();
	for (replacement, original) in [
		(first.as_ref().unwrap(), &b"config before"[..]),
		(second.as_ref().unwrap(), &b"compose before"[..]),
	] {
		let copy = replacement.backup.0.clone();
		assert!(error.contains(&copy.display().to_string()), "{error}");
		assert_eq!(fs::read(&copy).unwrap(), original);
	}
}
