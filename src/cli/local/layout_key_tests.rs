//! Tests for certificate and DKIM key regeneration and replacement.

use super::test_support::{fresh_dir, load_for_test};
use super::{DEFAULT_PORT_BASE, layout, prepare};

/// Pin: a directory with a valid marker, a non-empty `cert.pem` and an
/// empty `key.pem` is treated as a partial first-run. `prepare` must
/// regenerate the cert/key pair (both halves, because the runtime needs
/// both), and the new `key.pem` must load through `Config::load`. A
/// skip-if-exists check without a length check would accept the empty
/// `key.pem` and leave the runtime unable to bind a TLS listener.
#[test]
fn empty_key_pem_is_treated_as_missing_and_regenerated() {
	let dir = fresh_dir("empty-key");
	let _ = prepare(dir.path(), DEFAULT_PORT_BASE).expect("first prepare");

	let cert_path = dir.path().join("cert.pem");
	let key_path = dir.path().join("key.pem");
	let cert_before = std::fs::read(&cert_path).expect("read cert before");
	std::fs::write(&key_path, b"").expect("truncate key");

	let prepared = prepare(dir.path(), DEFAULT_PORT_BASE).expect("prepare retries");
	assert!(
		prepared.password.is_none(),
		"the credential pair was reused; only the cert/key pair was regenerated"
	);
	let key_after = std::fs::read(&key_path).expect("read key after");
	assert!(
		!key_after.is_empty(),
		"key.pem must be regenerated as non-empty"
	);
	let cert_after = std::fs::read(&cert_path).expect("read cert after");
	// `assert_ne!` would Debug-print both PEM byte arrays on
	// failure and dump the public key material into the CI log.
	// The boolean form names the outcome and reports the lengths
	// only, which is enough to diagnose a stuck cert step.
	assert!(
		cert_before != cert_after,
		"cert.pem must be regenerated alongside key.pem so the pair is consistent \
		 (lengths {} and {})",
		cert_before.len(),
		cert_after.len(),
	);
	let _ = load_for_test(&dir.path().join("mail.toml")).expect("mail.toml loads");
}

/// Pin: same shape as `empty_key_pem_is_treated_as_missing_and_regenerated`
/// but for `dkim.pem`. A zero-length DKIM key is treated as missing and
/// regenerated; the new key must be non-empty.
#[test]
fn empty_dkim_pem_is_treated_as_missing_and_regenerated() {
	let dir = fresh_dir("empty-dkim");
	let _ = prepare(dir.path(), DEFAULT_PORT_BASE).expect("first prepare");

	let dkim_path = dir.path().join("dkim.pem");
	std::fs::write(&dkim_path, b"").expect("truncate dkim");

	let prepared = prepare(dir.path(), DEFAULT_PORT_BASE).expect("prepare retries");
	assert!(
		prepared.password.is_none(),
		"the credential pair was reused; only the DKIM key was regenerated"
	);
	let dkim_after = std::fs::read(&dkim_path).expect("read dkim after");
	assert!(
		!dkim_after.is_empty(),
		"dkim.pem must be regenerated as non-empty"
	);
	let _ = load_for_test(&dir.path().join("mail.toml")).expect("mail.toml loads");
}

/// Pin: `write_dkim_key` over a path whose final name already exists as
/// a regular file succeeds and replaces the content. An exclusive
/// `create_new(true)` inside `write_with_mode` would fail with
/// `AlreadyExists` in this situation, so a second call to `prepare`
/// against a directory that already had a `dkim.pem` could not replace
/// it. The atomic-replace path writes through a sibling temp and
/// renames over the target, so a regular file at the final name is
/// never a blocker.
#[test]
fn write_dkim_key_replaces_an_existing_regular_file() {
	let dir = fresh_dir("dkim-replace");
	let dkim_path = dir.path().join("dkim.pem");
	std::fs::write(&dkim_path, b"stale from an older run").expect("seed dkim");

	layout::write_dkim_key(&dkim_path).expect("write_dkim_key replaces an existing file");

	let body = std::fs::read(&dkim_path).expect("read dkim after");
	assert_ne!(
		body, b"stale from an older run",
		"the seed must have been replaced, not preserved"
	);
	assert!(!body.is_empty(), "the new DKIM key must be non-empty");

	let leftover: Vec<_> = std::fs::read_dir(dir.path())
		.expect("readdir")
		.flatten()
		.filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
		.collect();
	assert!(
		leftover.is_empty(),
		"no sibling temp may remain, found {leftover:?}"
	);
}
