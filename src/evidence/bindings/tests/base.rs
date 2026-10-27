use std::os::unix::fs::PermissionsExt;

use super::*;

#[test]
fn bindings_round_trip_and_name_credentials_by_their_hash() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert_eq!(load(dir.path()).expect("empty"), Bindings::default());
	let first = app_password_key("$argon2id$v=19$m=19456,t=2,p=1$aaaa$bbbb");
	let reused_label = app_password_key("$argon2id$v=19$m=19456,t=2,p=1$cccc$dddd");
	assert_ne!(
		first, reused_label,
		"a new credential under the same label is another key"
	);
	update(dir.path(), |bindings| {
		bindings
			.accounts
			.insert("notices".into(), MailClass::Transactional);
		bindings
			.credentials
			.insert(first.clone(), MailClass::Marketing);
	})
	.expect("update");
	let set = BindingSet::open(dir.path()).expect("open");
	assert_eq!(set.account("NOTICES"), Some(MailClass::Transactional));
	assert_eq!(set.credential(&first), Some(MailClass::Marketing));
	assert_eq!(set.credential(&reused_label), None);
	let mode = std::fs::metadata(dir.path().join(FILE))
		.expect("stat")
		.permissions()
		.mode();
	assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn api_keys_are_named_by_the_stored_digest_of_their_token() {
	let token = crate::test_fixtures::fresh_secret();
	let stored = format!("sha256:{}", to_hex(&sha256(token.as_bytes())));
	assert_eq!(api_key_key_of_token(&token), api_key_key(&stored));
}

#[test]
fn a_file_others_can_write_is_refused_and_the_last_good_bindings_stay() {
	let dir = tempfile::tempdir().expect("tempdir");
	update(dir.path(), |bindings| {
		bindings
			.accounts
			.insert("notices".into(), MailClass::Transactional);
	})
	.expect("update");
	let set = BindingSet::open(dir.path()).expect("open");
	std::fs::set_permissions(
		dir.path().join(FILE),
		std::fs::Permissions::from_mode(0o666),
	)
	.expect("chmod");
	assert_eq!(
		load(dir.path()).expect_err("loose").kind(),
		std::io::ErrorKind::PermissionDenied
	);
	// Touch it so the set notices the change.
	let later = std::time::SystemTime::now() + std::time::Duration::from_secs(5);
	let file = std::fs::File::options()
		.append(true)
		.open(dir.path().join(FILE))
		.expect("open");
	file.set_modified(later).expect("mtime");
	assert_eq!(set.account("notices"), Some(MailClass::Transactional));
	assert_eq!(
		set.error().as_deref(),
		Some("class bindings are writable by other users: refused")
	);
}

#[test]
fn a_malformed_file_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::write(dir.path().join(FILE), r#"{"accounts":{"a":"elevated"}}"#).expect("write");
	std::fs::set_permissions(
		dir.path().join(FILE),
		std::fs::Permissions::from_mode(0o600),
	)
	.expect("chmod");
	assert_eq!(
		load(dir.path()).expect_err("unknown class").kind(),
		std::io::ErrorKind::InvalidData
	);
	assert!(
		BindingSet::open(dir.path()).is_err(),
		"no last good copy: refuse to start"
	);
}
