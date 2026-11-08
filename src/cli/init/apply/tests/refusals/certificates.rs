//! The certificate and OAuth key pairs `init` finds half-written: the
//! apply phase must repair what it can and refuse what it cannot.

use super::super::helpers::errors::{answers_minimal, apply_error_name};
use super::*;

/// Finding 3 (private only): when the OAuth private key exists but
/// the public key is missing, apply must derive the matching public
/// key from the existing private material and write it, reusing the
/// private key byte for byte. The orphan public key test asserts the
/// pair stays consistent.
#[cfg(unix)]
#[test]
fn apply_derives_missing_oauth_public_from_existing_private() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	std::fs::create_dir_all(&keys_dir).expect("keys dir");
	let outcome = apply(&answers_minimal(&data_dir, &config_path));
	assert!(outcome.error.is_none(), "first run: {:?}", outcome.error);
	let private = std::fs::read(crate::cli::init::host_secrets::oauth_signing_key(&data_dir))
		.expect("read private");
	let public = std::fs::read(keys_dir.join("oauth_public.key")).expect("read public");
	let private_first = private.clone();
	std::fs::remove_file(keys_dir.join("oauth_public.key")).expect("rm public");
	let outcome2 = apply(&answers_minimal(&data_dir, &config_path));
	assert!(outcome2.error.is_none(), "second run: {:?}", outcome2.error);
	let private_after = std::fs::read(crate::cli::init::host_secrets::oauth_signing_key(&data_dir))
		.expect("read private");
	let public_after = std::fs::read(keys_dir.join("oauth_public.key")).expect("read public");
	// Comparing PKCS#8 / SPKI byte arrays with `assert_eq!` would
	// Debug-print the full private key on mismatch, dumping it into
	// the CI log. A boolean assertion pins the same invariant
	// without carrying the bytes.
	assert!(
		private_first == private_after,
		"the private key must not be regenerated when only the public is missing"
	);
	assert!(
		public == public_after,
		"the derived public key must match the one the first run wrote"
	);
}

/// Finding 3 (public only): when the OAuth public key exists but
/// the private key is missing, apply must refuse with a recoverable
/// diagnostic rather than mint a fresh unrelated private key. The
/// plan and the apply phase must agree on the decision.
#[cfg(unix)]
#[test]
fn apply_refuses_when_only_oauth_public_survives() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	std::fs::create_dir_all(&keys_dir).expect("keys dir");
	let outcome = apply(&answers_minimal(&data_dir, &config_path));
	assert!(outcome.error.is_none(), "first run: {:?}", outcome.error);
	let public_before = std::fs::read(keys_dir.join("oauth_public.key")).expect("read public");
	std::fs::remove_file(crate::cli::init::host_secrets::oauth_signing_key(&data_dir))
		.expect("rm private");
	let outcome2 = apply(&answers_minimal(&data_dir, &config_path));
	let err = outcome2
		.error
		.expect("apply must refuse when only the public key survives");
	let ApplyError::OAuthPairIncomplete(message) = &err else {
		panic!(
			"expected OAuthPairIncomplete, got {}",
			apply_error_name(&err)
		);
	};
	assert!(
		message.contains("oauth_signing.key"),
		"the diagnostic must name the missing private key: {message}"
	);
	// Public key bytes must be unchanged: refusing the run is not
	// an excuse to overwrite the surviving material.
	let public_after = std::fs::read(keys_dir.join("oauth_public.key")).expect("read public");
	// Comparing SPKI byte arrays with `assert_eq!` would
	// Debug-print the full public key on mismatch. A boolean
	// assertion pins the same invariant without carrying the bytes.
	assert!(public_before == public_after);
	assert!(
		!crate::cli::init::host_secrets::oauth_signing_key(&data_dir).exists(),
		"a fresh private key must NOT have been written when only the public survived"
	);
}

/// Finding 3 (mismatched pair): when both halves exist but they do
/// not correspond, apply must refuse rather than silently keep an
/// unusable pair on disk.
#[cfg(unix)]
#[test]
fn apply_refuses_when_oauth_pair_does_not_correspond() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	std::fs::create_dir_all(&keys_dir).expect("keys dir");
	// Run twice to collect two independent private keys, then pair
	// the first private with the second public.
	let outcome_a = apply(&answers_minimal(&data_dir, &config_path));
	assert!(outcome_a.error.is_none(), "run a: {:?}", outcome_a.error);
	let private_a = std::fs::read(crate::cli::init::host_secrets::oauth_signing_key(&data_dir))
		.expect("a private");
	let _ = std::fs::remove_file(crate::cli::init::host_secrets::oauth_signing_key(&data_dir));
	let _ = std::fs::remove_file(keys_dir.join("oauth_public.key"));
	let outcome_b = apply(&answers_minimal(&data_dir, &config_path));
	assert!(outcome_b.error.is_none(), "run b: {:?}", outcome_b.error);
	let public_b = std::fs::read(keys_dir.join("oauth_public.key")).expect("b public");
	// Build the mismatched pair: private_a + public_b.
	let _ = std::fs::remove_file(crate::cli::init::host_secrets::oauth_signing_key(&data_dir));
	std::fs::write(
		crate::cli::init::host_secrets::oauth_signing_key(&data_dir),
		&private_a,
	)
	.expect("write private_a");
	let outcome = apply(&answers_minimal(&data_dir, &config_path));
	let err = outcome.error.expect("apply must refuse a mismatched pair");
	let ApplyError::OAuthPairMismatch = &err else {
		panic!("expected OAuthPairMismatch, got {}", apply_error_name(&err));
	};
	let public_after = std::fs::read(keys_dir.join("oauth_public.key")).expect("read public");
	let private_after = std::fs::read(crate::cli::init::host_secrets::oauth_signing_key(&data_dir))
		.expect("read private");
	// Comparing the byte arrays with `assert_eq!` would Debug-print
	// the full PKCS#8 / SPKI on mismatch, dumping the private key
	// (or its modified form) into the CI log. A boolean assertion
	// pins the same invariant without carrying the bytes.
	assert!(
		public_after == public_b,
		"public key bytes must be untouched"
	);
	assert!(
		private_after == private_a,
		"private key bytes must be untouched"
	);
}

/// Finding 4 (missing cert): when only `key.pem` survives, apply
/// must rebuild a self-signed certificate from the existing key
/// without regenerating the key itself. The plan must describe
/// this state as `reuse key` + `generate cert` so the operator
/// sees the partial recovery in advance.
#[cfg(unix)]
#[test]
fn apply_regenerates_cert_from_existing_key_when_only_key_survives() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	let first = apply(&answers_minimal(&data_dir, &config_path));
	assert!(first.error.is_none(), "first run: {:?}", first.error);
	let key_path = keys_dir.join("key.pem");
	let cert_path = keys_dir.join("cert.pem");
	let key_before = std::fs::read(&key_path).expect("read key");
	let _ = std::fs::remove_file(&cert_path);
	let second = apply(&answers_minimal(&data_dir, &config_path));
	assert!(
		second.error.is_none(),
		"second run must succeed: {:?}",
		second.error
	);
	let key_after = std::fs::read(&key_path).expect("read key");
	// Comparing PEM byte arrays with `assert_eq!` would Debug-print
	// the full private key on mismatch, dumping it into the CI log.
	// A boolean assertion pins the same invariant without carrying
	// the bytes.
	assert!(
		key_before == key_after,
		"the existing private key must not be regenerated when only the cert is missing"
	);
	assert!(
		cert_path.exists(),
		"a replacement certificate must have been written"
	);
	let pem = std::str::from_utf8(&key_after).expect("utf8");
	assert!(
		pem.contains("BEGIN"),
		"key.pem must still be a PEM document"
	);
}

/// Finding 4 (missing key): when only `cert.pem` survives, apply
/// must refuse with a recoverable diagnostic rather than overwrite
/// the certificate or invent a fresh key.
#[cfg(unix)]
#[test]
fn apply_refuses_when_only_cert_survives() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	let first = apply(&answers_minimal(&data_dir, &config_path));
	assert!(first.error.is_none(), "first run: {:?}", first.error);
	let key_path = keys_dir.join("key.pem");
	let cert_path = keys_dir.join("cert.pem");
	let cert_before = std::fs::read(&cert_path).expect("read cert");
	let _ = std::fs::remove_file(&key_path);
	let second = apply(&answers_minimal(&data_dir, &config_path));
	let err = second
		.error
		.expect("apply must refuse when only the cert survives");
	let ApplyError::CertPairIncomplete(message) = &err else {
		panic!(
			"expected CertPairIncomplete, got {}",
			apply_error_name(&err)
		);
	};
	assert!(
		message.contains("key.pem"),
		"the diagnostic must name the missing key: {message}"
	);
	let cert_after = std::fs::read(&cert_path).expect("read cert");
	// Comparing PEM byte arrays with `assert_eq!` would Debug-print
	// the full certificate on mismatch. A boolean assertion pins
	// the same invariant without carrying the bytes.
	assert!(
		cert_before == cert_after,
		"the surviving certificate must NOT be overwritten"
	);
	assert!(
		!key_path.exists(),
		"a fresh private key must NOT have been written"
	);
}
