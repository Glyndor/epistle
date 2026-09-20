//! Coverage-focused tests for apply-phase refusal paths: every test
//! in this file drives `apply` (or `apply_plan::plan` for the
//! preflight checks) with a credential, key, or config shape the
//! apply phase must refuse, and asserts the matching `ApplyError`
//! variant. Lifted into a sibling because the original apply
//! failure file was at the per-file line limit; the apply-config
//! side (reconcile, write_validated_config, plan refusals) was
//! lifted further into `apply_failures_tests_c.rs` when this file
//! itself reached the limit. The splits share the helpers from
//! `apply_failures_tests.rs` through the `super` import and
//! re-implement only what the parent does not already expose.
//! Every test in this file was watched red with a one-line
//! sabotage swap and restored.

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use super::tests_failures::answers_minimal;
use super::*;

/// Non-UTF-8 bytes in the surviving oauth private key must surface
/// as `OAuthPairIncomplete` from the plan so the operator sees the
/// refusal before confirming. The plan validates the pair before
/// any effect, exactly the way the apply phase does.
#[test]
fn plan_refuses_oauth_private_key_that_is_not_utf8() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	std::fs::create_dir_all(&keys_dir).expect("keys dir");
	let bad = [0xff, 0xfe, 0xfd, 0xfc, 0xfb];
	std::fs::write(keys_dir.join("oauth_signing.key"), bad).expect("write bad private");
	std::fs::write(keys_dir.join("oauth_public.key"), b"public").expect("write public");
	let plan = apply_plan::plan(&answers_minimal(&data_dir, &config_path));
	let err = plan.expect_err("plan must refuse non-utf-8 oauth private");
	let ApplyError::OAuthPairIncomplete(message) = &err else {
		panic!("expected OAuthPairIncomplete, got {err:?}");
	};
	assert!(
		message.contains("not valid utf-8"),
		"the diagnostic must name the utf-8 problem: {message}"
	);
}

/// Non-UTF-8 bytes in the surviving oauth public key must surface
/// as `OAuthPairIncomplete` from the plan. Without the explicit
/// utf-8 check, the trim comparison would misreport the
/// mismatch as `OAuthPairMismatch` and the operator would not see
/// the real cause. The private key must therefore be a real
/// PKCS#8 ES256 document so the plan reaches the public-half
/// utf-8 check.
#[test]
fn plan_refuses_oauth_public_key_that_is_not_utf8() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	std::fs::create_dir_all(&keys_dir).expect("keys dir");
	let outcome = apply(&answers_minimal(&data_dir, &config_path));
	assert!(outcome.error.is_none(), "mint: {:?}", outcome.error);
	let bad = [0xff, 0xfe, 0xfd, 0xfc, 0xfb];
	std::fs::write(keys_dir.join("oauth_public.key"), bad).expect("write bad public");
	let plan = apply_plan::plan(&answers_minimal(&data_dir, &config_path));
	let err = plan.expect_err("plan must refuse non-utf-8 oauth public");
	let ApplyError::OAuthPairIncomplete(message) = &err else {
		panic!("expected OAuthPairIncomplete, got {err:?}");
	};
	assert!(
		message.contains("not valid utf-8"),
		"the diagnostic must name the utf-8 problem on the public half: {message}"
	);
}

/// A surviving oauth private key that is utf-8 but not a valid
/// PKCS#8 ES256 document must surface as `OAuthPairIncomplete`
/// from the plan with the "not a valid PKCS#8" wording, not as
/// the more generic `OAuthPairMismatch`.
#[test]
fn plan_refuses_oauth_private_key_that_is_not_a_pkcs8_es256_document() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	std::fs::create_dir_all(&keys_dir).expect("keys dir");
	std::fs::write(keys_dir.join("oauth_signing.key"), b"definitely not a key")
		.expect("write private");
	std::fs::write(keys_dir.join("oauth_public.key"), b"public").expect("write public");
	let plan = apply_plan::plan(&answers_minimal(&data_dir, &config_path));
	let err = plan.expect_err("plan must refuse a non-PKCS#8 oauth private");
	let ApplyError::OAuthPairIncomplete(message) = &err else {
		panic!("expected OAuthPairIncomplete, got {err:?}");
	};
	assert!(
		message.contains("PKCS#8"),
		"the diagnostic must name the PKCS#8 problem: {message}"
	);
}

/// Plan-phase mismatched-pair detection: when both oauth halves
/// are valid utf-8 PKCS#8 documents but they do not correspond,
/// the plan must surface `OAuthPairMismatch` so the operator sees
/// the refusal before any effect.
#[test]
fn plan_refuses_a_mismatched_oauth_pair_with_both_keys_valid_utf8() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	std::fs::create_dir_all(&keys_dir).expect("keys dir");
	// Mint two independent PKCS#8 ES256 keypairs and pair the
	// first private with the second public. Both halves are
	// valid utf-8 documents, so the mismatch check is the only
	// failure path that fires.
	let (private_a, _public_a) = crate::cli::util::generate_oauth_keypair().expect("mint pair a");
	let (_private_b, public_b) = crate::cli::util::generate_oauth_keypair().expect("mint pair b");
	std::fs::write(keys_dir.join("oauth_signing.key"), &private_a).expect("write private_a");
	std::fs::write(keys_dir.join("oauth_public.key"), public_b.as_bytes()).expect("write public_b");
	let plan = apply_plan::plan(&answers_minimal(&data_dir, &config_path));
	let err = plan.expect_err("plan must refuse a mismatched oauth pair");
	let ApplyError::OAuthPairMismatch = &err else {
		panic!("expected OAuthPairMismatch, got {err:?}");
	};
}

/// Apply-phase mirror of the plan-phase utf-8 check: a non-UTF-8
/// oauth private key must surface as `OAuthPairIncomplete` from
/// the apply phase too, so the operator who skips the plan (the
/// `--answers` file path) still sees the real cause instead of
/// the more generic `OAuthPairMismatch` once the trim comparison
/// misfires.
#[cfg(unix)]
#[test]
fn apply_refuses_oauth_private_key_that_is_not_utf8() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	std::fs::create_dir_all(&keys_dir).expect("keys dir");
	let bad = [0xff, 0xfe, 0xfd, 0xfc, 0xfb];
	std::fs::write(keys_dir.join("oauth_signing.key"), bad).expect("write bad private");
	let outcome = apply(&answers_minimal(&data_dir, &config_path));
	let err = outcome
		.error
		.expect("apply must refuse non-utf-8 oauth private");
	let ApplyError::OAuthPairIncomplete(message) = &err else {
		panic!("expected OAuthPairIncomplete, got {err:?}");
	};
	assert!(
		message.contains("not valid utf-8"),
		"the diagnostic must name the utf-8 problem: {message}"
	);
}

/// Apply-phase mirror for the public half: a non-UTF-8 oauth
/// public key must surface as `OAuthPairIncomplete`. The
/// private key must therefore be a real PKCS#8 ES256 document
/// so the apply phase reaches the public-half utf-8 check.
#[cfg(unix)]
#[test]
fn apply_refuses_oauth_public_key_that_is_not_utf8() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	std::fs::create_dir_all(&keys_dir).expect("keys dir");
	let outcome = apply(&answers_minimal(&data_dir, &config_path));
	assert!(outcome.error.is_none(), "mint: {:?}", outcome.error);
	let bad = [0xff, 0xfe, 0xfd, 0xfc, 0xfb];
	std::fs::write(keys_dir.join("oauth_public.key"), bad).expect("write bad public");
	let outcome = apply(&answers_minimal(&data_dir, &config_path));
	let err = outcome
		.error
		.expect("apply must refuse non-utf-8 oauth public");
	let ApplyError::OAuthPairIncomplete(message) = &err else {
		panic!("expected OAuthPairIncomplete, got {err:?}");
	};
	assert!(
		message.contains("not valid utf-8"),
		"the diagnostic must name the utf-8 problem on the public half: {message}"
	);
}

/// Apply-phase mirror for the PKCS#8 check on the private key:
/// a utf-8 but non-PKCS#8 private key must surface as
/// `OAuthPairIncomplete` with the "not a valid PKCS#8" wording.
#[cfg(unix)]
#[test]
fn apply_refuses_oauth_private_key_that_is_not_a_pkcs8_es256_document() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	std::fs::create_dir_all(&keys_dir).expect("keys dir");
	std::fs::write(keys_dir.join("oauth_signing.key"), b"definitely not a key")
		.expect("write private");
	let outcome = apply(&answers_minimal(&data_dir, &config_path));
	let err = outcome
		.error
		.expect("apply must refuse non-PKCS#8 oauth private");
	let ApplyError::OAuthPairIncomplete(message) = &err else {
		panic!("expected OAuthPairIncomplete, got {err:?}");
	};
	assert!(
		message.contains("PKCS#8"),
		"the diagnostic must name the PKCS#8 problem: {message}"
	);
}

/// Calling `apply` directly with an existing config that the rest
/// of the CLI would refuse (here: a top-level unknown key while
/// the file is mode 0600) must surface `ConfigInvalid` with the
/// `Config::load` message. The plan path catches the same case
/// when `run()` is the entry point; the apply path catches it
/// when the caller drives `apply` directly. Both paths must
/// refuse.
#[cfg(unix)]
#[test]
fn apply_refuses_when_existing_config_has_an_unknown_top_level_key() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let outcome = apply(&answers_minimal(&data_dir, &config_path));
	assert!(outcome.error.is_none(), "seed: {:?}", outcome.error);
	let mut appended = std::fs::read_to_string(&config_path).expect("read");
	appended.insert_str(0, "# operator comment\noperator_note = \"keep me\"\n");
	std::fs::write(&config_path, &appended).expect("rewrite with unknown key");
	std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
		.expect("chmod 0600");
	let outcome = apply(&answers_minimal(&data_dir, &config_path));
	let err = outcome
		.error
		.expect("apply must refuse an invalid existing config");
	let ApplyError::ConfigInvalid(message) = &err else {
		panic!("expected ConfigInvalid, got {err:?}");
	};
	assert!(
		message.contains("operator_note"),
		"the diagnostic must name the unknown field: {message}"
	);
}

/// A surviving private key that is valid utf-8 but not a PEM
/// document (no `BEGIN PRIVATE KEY` marker) must surface as
/// `CertPairIncomplete` from `rcgen::KeyPair::from_pem` instead
/// of panicking. The apply phase must refuse with a recoverable
/// diagnostic; the operator can then delete the bad key and
/// retry, or restore a real one from backup.
#[cfg(unix)]
#[test]
fn apply_refuses_a_surviving_private_key_that_is_not_a_pem_document() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	let first = apply(&answers_minimal(&data_dir, &config_path));
	assert!(first.error.is_none(), "first run: {:?}", first.error);
	let key_path = keys_dir.join("key.pem");
	let cert_path = keys_dir.join("cert.pem");
	// Replace the surviving private key with a utf-8 document
	// that is not a PEM and remove the matching certificate so
	// the apply phase must reload the key. The
	// `CertPairIncomplete` branch fires from
	// `rcgen::KeyPair::from_pem`, which fails on non-PEM input.
	std::fs::write(&key_path, b"this is not a PEM key").expect("write bad key");
	let _ = std::fs::remove_file(&cert_path);
	let second = apply(&answers_minimal(&data_dir, &config_path));
	let err = second
		.error
		.expect("apply must refuse a non-PEM surviving private key");
	let ApplyError::CertPairIncomplete(message) = &err else {
		panic!("expected CertPairIncomplete, got {err:?}");
	};
	assert!(
		message.contains("key.pem"),
		"the diagnostic must name the bad private key: {message}"
	);
}

/// A surviving private key that is not even valid utf-8 must surface
/// as `CertPairIncomplete` from the utf-8 check, not panic, and the
/// operator must see a diagnostic naming the file. Removing the
/// matching certificate forces the apply phase to actually try
/// reloading the key.
#[cfg(unix)]
#[test]
fn apply_refuses_a_surviving_private_key_that_is_not_utf8() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	let first = apply(&answers_minimal(&data_dir, &config_path));
	assert!(first.error.is_none(), "first run: {:?}", first.error);
	let key_path = keys_dir.join("key.pem");
	let cert_path = keys_dir.join("cert.pem");
	let bad = [0xff, 0xfe, 0xfd, 0xfc, 0xfb];
	std::fs::write(&key_path, bad).expect("write bad key");
	let _ = std::fs::remove_file(&cert_path);
	let second = apply(&answers_minimal(&data_dir, &config_path));
	let err = second
		.error
		.expect("apply must refuse a non-utf-8 surviving private key");
	let ApplyError::CertPairIncomplete(message) = &err else {
		panic!("expected CertPairIncomplete, got {err:?}");
	};
	assert!(
		message.contains("utf-8"),
		"the diagnostic must name the utf-8 problem: {message}"
	);
}

/// A surviving oauth private key that the apply phase cannot read
/// must surface as `KeyWrite` so the operator sees the read failure
/// with the file path intact, rather than a panic. The condition is
/// built out of a filesystem shape the kernel refuses for every
/// uid: a directory at the path that the code expects to be a file.
/// `fs::read` on a directory returns `ErrorKind::IsADirectory` for
/// root and non-root alike; relying on `chmod 0000` would let the
/// test pass for the wrong reason when the binary runs as root
/// (the Debian package build).
#[cfg(unix)]
#[test]
fn apply_refuses_when_surviving_oauth_private_key_is_unreadable() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	let first = apply(&answers_minimal(&data_dir, &config_path));
	assert!(first.error.is_none(), "first run: {:?}", first.error);
	let oauth_private = keys_dir.join("oauth_signing.key");
	let _ = std::fs::remove_file(&oauth_private);
	std::fs::create_dir(&oauth_private).expect("mkdir at oauth_private");
	let second = apply(&answers_minimal(&data_dir, &config_path));
	let err = second
		.error
		.expect("apply must refuse an unreadable surviving oauth private key");
	let ApplyError::KeyWrite(path, _io) = &err else {
		panic!("expected KeyWrite, got {err:?}");
	};
	assert_eq!(
		path, &oauth_private,
		"the diagnostic must name the unreadable oauth private key"
	);
}

/// A surviving oauth public key that the apply phase cannot read
/// must surface as `KeyWrite` from the apply phase. The condition
/// is built out of a filesystem shape the kernel refuses for every
/// uid: a directory at the path the code expects to be a file.
/// Without the explicit error branch the read failure would
/// propagate as a panic.
#[cfg(unix)]
#[test]
fn apply_refuses_when_surviving_oauth_public_key_is_unreadable() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	let first = apply(&answers_minimal(&data_dir, &config_path));
	assert!(first.error.is_none(), "first run: {:?}", first.error);
	let oauth_public = keys_dir.join("oauth_public.key");
	let _ = std::fs::remove_file(&oauth_public);
	std::fs::create_dir(&oauth_public).expect("mkdir at oauth_public");
	let second = apply(&answers_minimal(&data_dir, &config_path));
	let err = second
		.error
		.expect("apply must refuse an unreadable surviving oauth public key");
	let ApplyError::KeyWrite(path, _io) = &err else {
		panic!("expected KeyWrite, got {err:?}");
	};
	assert_eq!(
		path, &oauth_public,
		"the diagnostic must name the unreadable oauth public key"
	);
}
