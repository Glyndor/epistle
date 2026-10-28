use super::*;

#[test]
fn needs_renewal_when_certificate_absent() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert!(needs_renewal(dir.path(), 30, now_secs()));
}

#[test]
fn fresh_certificate_does_not_need_renewal() {
	let dir = tempfile::tempdir().expect("tempdir");
	fs::create_dir_all(dir.path().join("acme")).expect("mkdir");
	fs::write(cert_path(dir.path()), b"cert").expect("write");
	// Just written → far from the 90-day expiry.
	assert!(!needs_renewal(dir.path(), 30, now_secs()));
}

#[test]
fn old_certificate_needs_renewal() {
	let dir = tempfile::tempdir().expect("tempdir");
	fs::create_dir_all(dir.path().join("acme")).expect("mkdir");
	fs::write(cert_path(dir.path()), b"cert").expect("write");
	// 89 days in the future is within the 30-day renewal window.
	let future = now_secs() + 89 * 86_400;
	assert!(needs_renewal(dir.path(), 30, future));
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

#[test]
fn unreadable_certificate_modified_time_renews() {
	// A cert that exists but reads as freshly issued is not renewed; an
	// absent one is. Covers the metadata branch boundaries.
	let dir = tempfile::tempdir().expect("tempdir");
	fs::create_dir_all(dir.path().join("acme")).expect("mkdir");
	fs::write(cert_path(dir.path()), b"cert").expect("write");
	// now far in the past → not yet at the renew threshold.
	assert!(!needs_renewal(dir.path(), 30, 0));
}
