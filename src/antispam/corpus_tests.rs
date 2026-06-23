//! Unit tests for the corpus key handling and token hashing (no database).

use super::*;

#[test]
fn hash_is_deterministic_and_key_dependent() {
	let k1 = [1u8; 32];
	let k2 = [2u8; 32];
	// Same key + token -> same hash (so lookups work).
	assert_eq!(hash_token(&k1, "viagra"), hash_token(&k1, "viagra"));
	// Different tokens -> different hashes.
	assert_ne!(hash_token(&k1, "viagra"), hash_token(&k1, "meeting"));
	// Different keys -> different hashes (per-instance confidentiality).
	assert_ne!(hash_token(&k1, "viagra"), hash_token(&k2, "viagra"));
	// The hash is 64 hex chars and never contains the plaintext.
	let h = hash_token(&k1, "viagra");
	assert_eq!(h.len(), 64, "{h}");
	assert!(!h.contains("viagra"), "{h}");
	assert!(h.chars().all(|c| c.is_ascii_hexdigit()), "{h}");
}

#[test]
fn key_persists_and_reloads() {
	let dir = tempfile::tempdir().expect("tempdir");
	let first = load_or_create_key(dir.path()).expect("generate");
	let second = load_or_create_key(dir.path()).expect("reload");
	// The same key is returned on the second call (stable across restarts).
	assert_eq!(first, second);
}

#[cfg(unix)]
#[test]
fn key_file_is_owner_only() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");
	load_or_create_key(dir.path()).expect("generate");
	let mode = std::fs::metadata(dir.path().join(KEY_FILE))
		.expect("stat")
		.permissions()
		.mode();
	assert_eq!(mode & 0o077, 0, "key file must not be group/world readable");
}
