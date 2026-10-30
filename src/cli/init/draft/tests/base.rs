//! Private persistence and credential exclusion checks.

use super::*;

#[test]
fn draft_round_trips_private_answers_and_rejects_secret_fields() {
	let dir = tempfile::tempdir().unwrap();
	let store = Store {
		directory: dir.path().join("state"),
	};
	let answers = Answers::from([("hostname".into(), "mail.example.org".into())]);
	store.save(&answers).unwrap();
	assert_eq!(store.load().unwrap(), answers);
	assert_eq!(fs::metadata(store.path()).unwrap().mode() & 0o777, 0o600);
	assert_eq!(
		fs::metadata(&store.directory).unwrap().mode() & 0o777,
		0o700
	);
	assert!(
		store
			.save(&Answers::from([(
				"password".into(),
				"never persist".into()
			)]))
			.is_err()
	);
	assert_eq!(store.load().unwrap(), answers);
	store.remove().unwrap();
	assert!(store.load().unwrap().is_empty());
}

#[test]
fn linked_or_public_drafts_are_refused_without_reading_the_contents() {
	let dir = tempfile::tempdir().unwrap();
	let store = Store {
		directory: dir.path().join("state"),
	};
	store.save(&Answers::new()).unwrap();
	fs::remove_file(store.path()).unwrap();
	let other = dir.path().join("other");
	fs::write(&other, "{}").unwrap();
	fs::set_permissions(&other, fs::Permissions::from_mode(0o600)).unwrap();
	std::os::unix::fs::symlink(&other, store.path()).unwrap();
	assert!(store.load().is_err());
	fs::remove_file(store.path()).unwrap();
	fs::write(store.path(), "{}").unwrap();
	use std::os::unix::fs::PermissionsExt;
	fs::set_permissions(store.path(), fs::Permissions::from_mode(0o644)).unwrap();
	assert!(store.load().is_err());
}
