use super::*;

#[test]
fn needs_renewal_when_certificate_absent() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert!(needs_renewal(dir.path(), 30, now_secs()));
}

#[test]
fn account_key_persists_and_reloads() {
	let dir = tempfile::tempdir().expect("tempdir");
	let a = load_or_create_account_key(dir.path()).expect("create");
	let b = load_or_create_account_key(dir.path()).expect("reload");
	// Reload returns the same key (same JWK), not a new one.
	assert_eq!(a.jwk(), b.jwk());
}

#[cfg(unix)]
#[test]
fn account_key_is_written_owner_only() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");
	load_or_create_account_key(dir.path()).expect("create");
	let mode = fs::metadata(account_key_path(dir.path()))
		.expect("metadata")
		.permissions()
		.mode();
	// No group/other bits: the key never had a readable window.
	assert_eq!(mode & 0o077, 0, "key mode {mode:#o} is too permissive");
	// The temp file used for the atomic write is cleaned up.
	assert!(!account_key_path(dir.path()).with_extension("tmp").exists());
}

#[test]
fn corrupt_account_key_is_rejected() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = account_key_path(dir.path());
	fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");

	// Not valid base64 → decode error.
	fs::write(&path, "not base64 !!!").expect("write");
	assert!(load_or_create_account_key(dir.path()).is_err());

	// Valid base64 but not a PKCS#8 key → parse error.
	fs::write(&path, B64.encode(b"not a key")).expect("write");
	assert!(load_or_create_account_key(dir.path()).is_err());
}

/// The certificates container keeps the key outside data_dir; the same file
/// is loaded back rather than replaced.
#[test]
fn account_key_at_a_chosen_path_persists_and_reloads() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("secrets").join("acme_account.key");
	fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
	let a = load_or_create_account_key_at(&path).expect("create");
	let b = load_or_create_account_key_at(&path).expect("reload");
	assert_eq!(a.jwk(), b.jwk());
	assert!(!account_key_path(dir.path()).exists());
}

/// A key that cannot be read is not a key that does not exist: only a missing file
/// makes a new key, any other error is reported and the good key is left alone.
#[test]
fn an_account_key_that_cannot_be_read_is_not_replaced() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("account.key");
	load_or_create_account_key_at(&path).expect("create");
	let good = std::fs::read(&path).expect("read the key");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod");
	if std::fs::read(&path).is_ok() {
		// root reads anything: the case cannot be built here.
		return;
	}
	assert!(
		load_or_create_account_key_at(&path).is_err(),
		"an unreadable key is an error"
	);
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod back");
	assert_eq!(
		std::fs::read(&path).expect("read again"),
		good,
		"the good key was not replaced"
	);
}

#[test]
fn a_missing_account_key_is_created() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("acme").join("account.key");
	std::fs::create_dir_all(path.parent().unwrap()).expect("dir");
	assert!(!path.exists());
	load_or_create_account_key_at(&path).expect("create");
	assert!(path.is_file());
}
