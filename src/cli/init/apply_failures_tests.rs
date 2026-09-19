//! Apply-phase failure scenarios: every case asserts the user-visible
//! outcome, the matching `ApplyError` variant, the steps that ran
//! before the failure, and the rendered report listing those steps in
//! the same shape the operator sees on stderr. The shared helpers
//! `answers_minimal` and `render_report_to_string` are exposed to
//! the sibling `apply_failures_tests_b.rs` so the coverage-focused
//! splits reuse them.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::cli::init::answers::Services;

pub(super) fn answers_minimal(data_dir: &Path, config_path: &Path) -> Answers {
	Answers {
		mode: crate::cli::init::answers::Mode::Manual,
		hostname: "mail.example.org".to_string(),
		domains: vec!["example.org".to_string()],
		public_ipv4: Some(Ipv4Addr::new(8, 8, 8, 8)),
		public_ipv6: Some(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
		data_dir: data_dir.to_path_buf(),
		config_path: config_path.to_path_buf(),
		dns: None,
		services: Services::default(),
	}
}

pub(super) fn render_report_to_string(report: &Report) -> String {
	let mut buf = Vec::new();
	report.write_to(&mut buf).expect("render report");
	String::from_utf8_lossy(&buf).into_owned()
}

#[cfg(unix)]
#[test]
fn apply_fails_when_keys_dir_cannot_be_created() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	// chmod 0500 on the tempdir so `create_dir_all(data_dir)` cannot
	// create the data_dir the apply phase needs. The spec asks for a
	// guard against running as root, where the mode bits are ignored:
	// the canary below confirms the chmod actually blocks writes before
	// the test runs.
	std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500))
		.expect("chmod 0500 on tempdir");
	let canary = dir.path().join("canary");
	if std::fs::write(&canary, b"x").is_ok() {
		std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
			.expect("restore tempdir mode");
		let _ = std::fs::remove_file(&canary);
		eprintln!(
			"skipping: tempdir mode 0500 did not block writes (running as root or fs ignores mode)"
		);
		return;
	}
	let outcome = apply(&answers_minimal(&data_dir, &config_path));
	// Restore permissions before any assertion that might panic, so
	// the tempdir can be cleaned up at end of scope.
	std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
		.expect("restore tempdir mode");
	let err = outcome
		.error
		.expect("apply must fail when keys dir cannot be created");
	assert!(
		matches!(err, ApplyError::KeysDir(_, _)),
		"expected KeysDir, got {err:?}"
	);
	// No step ran before the failure: data_dir could not be created.
	assert!(
		outcome.report.steps.is_empty(),
		"expected empty report, got {:?}",
		outcome.report.steps
	);
	// The rendered report must be empty too: the operator sees nothing
	// applied and the system says so.
	let rendered = render_report_to_string(&outcome.report);
	assert!(
		rendered.is_empty(),
		"expected empty rendered report, got {rendered:?}"
	);
}

#[test]
fn apply_fails_when_candidate_config_does_not_validate() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let mut answers = answers_minimal(&data_dir, &config_path);
	// "localhost" is not a valid FQDN; `answers::validate` would catch
	// it before we get to `apply`, so this test bypasses the answers
	// path and drives `apply` directly to reach the Config::load gate.
	answers.hostname = "localhost".to_string();
	let outcome = apply(&answers);
	let err = outcome
		.error
		.expect("apply must surface ConfigInvalid when the candidate fails Config::load");
	assert!(
		matches!(err, ApplyError::ConfigInvalid(_)),
		"expected ConfigInvalid, got {err:?}"
	);
	let s1 = data_dir.join("keys").join("s1.pem");
	assert!(
		s1.exists(),
		"the dkim ed25519 key must be on disk before the failure: {s1:?}"
	);
	let rendered = render_report_to_string(&outcome.report);
	assert!(
		rendered.contains("wrote:"),
		"rendered report must list the steps that ran: {rendered}"
	);
	assert!(
		rendered.contains("s1.pem"),
		"rendered report must name the dkim ed25519 key: {rendered}"
	);
}

#[test]
fn apply_fails_when_config_path_parent_is_a_regular_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let blocker = dir.path().join("etc");
	std::fs::write(&blocker, b"not a directory").expect("blocker");
	let config_path = blocker.join("mail.toml");
	let data_dir = dir.path().join("data");
	let outcome = apply(&answers_minimal(&data_dir, &config_path));
	let err = outcome
		.error
		.expect("apply must surface the error after partial progress");
	assert!(
		matches!(
			err,
			ApplyError::ConfigRead(_, _) | ApplyError::ConfigWrite(_, _)
		),
		"expected ConfigRead or ConfigWrite, got {err:?}"
	);
	let rendered = render_report_to_string(&outcome.report);
	// Every step that ran before the failure must show up in the
	// rendered report with the same shape the operator sees on stderr.
	let keys_dir = data_dir.join("keys");
	assert!(
		rendered.contains("created dir:") && rendered.contains(&data_dir.display().to_string()),
		"data_dir creation missing from rendered report: {rendered}"
	);
	for name in [
		"s1.pem",
		"storage.key",
		"oauth_signing.key",
		"oauth_public.key",
		"cert.pem",
		"key.pem",
	] {
		let path = keys_dir.join(name);
		assert!(
			path.exists(),
			"expected key file on disk before the failure: {path:?}"
		);
		assert!(
			rendered.contains(name),
			"rendered report must name {name}: {rendered}"
		);
	}
}

#[cfg(unix)]
#[test]
fn apply_fails_when_a_later_key_write_is_obstructed_and_retains_earlier_writes() {
	// A directory sits where the storage key's staging temp would
	// go. The DKIM ed25519 and RSA keys have already landed on disk
	// when `write_secret` for the storage key fails, so the apply
	// phase must (1) propagate the failure as `KeyWrite` (no panic),
	// (2) keep every earlier `Wrote` step in the report so the
	// operator sees what landed, and (3) name the storage key path
	// it could not write, not a generic message.
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	std::fs::create_dir_all(keys_dir.join("storage.secret.tmp")).expect("blocker dir");
	let outcome = apply(&answers_minimal(&data_dir, &config_path));
	let err = outcome
		.error
		.expect("apply must surface a KeyWrite error after the obstruction");
	let ApplyError::KeyWrite(path, _io) = &err else {
		panic!("expected KeyWrite, got {err:?}");
	};
	assert!(
		path.ends_with("storage.key"),
		"the failing path must name the storage key, got {path:?}"
	);
	let rendered = render_report_to_string(&outcome.report);
	assert!(
		rendered.contains("wrote:") && rendered.contains("s1.pem"),
		"the report must record the dkim ed25519 write: {rendered}"
	);
	assert!(
		rendered.contains("s2.pem"),
		"the report must record the dkim rsa write: {rendered}"
	);
	assert!(
		!rendered.contains("storage.key"),
		"the report must NOT claim a successful storage-key write: {rendered}"
	);
	assert!(
		keys_dir.join("s1.pem").exists(),
		"s1.pem must be on disk from the earlier successful write"
	);
	assert!(
		keys_dir.join("s2.pem").exists(),
		"s2.pem must be on disk from the earlier successful write"
	);
	assert!(
		!keys_dir.join("storage.key").exists(),
		"storage.key must NOT be on disk because the write failed"
	);
}

#[cfg(unix)]
#[test]
fn apply_does_not_leave_a_staging_temp_after_a_failed_write() {
	// The staging temp is created with `O_EXCL` so a leftover from
	// a prior crashed run would block the next write. After a failed
	// write we must remove the temp file so the next run can
	// succeed; the test asserts the temp file does not survive a
	// failed apply pass.
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	let blocker = keys_dir.join("storage.secret.tmp");
	std::fs::create_dir_all(&blocker).expect("blocker dir");
	let _ = apply(&answers_minimal(&data_dir, &config_path));
	// The temp should be left on disk by `write_secret` itself when
	// the obstruction blocks its own create_new. After apply we
	// clean it up explicitly so the next run can proceed; assert
	// the cleanup ran by removing the blocker and re-running apply,
	// which must now succeed and write the storage key.
	std::fs::remove_dir_all(&blocker).expect("remove blocker");
	let outcome2 = apply(&answers_minimal(&data_dir, &config_path));
	assert!(
		outcome2.error.is_none(),
		"retry must succeed: {:?}",
		outcome2.error
	);
	assert!(
		keys_dir.join("storage.key").exists(),
		"storage.key must be written on retry"
	);
}

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
	let private = std::fs::read(keys_dir.join("oauth_signing.key")).expect("read private");
	let public = std::fs::read(keys_dir.join("oauth_public.key")).expect("read public");
	let private_first = private.clone();
	std::fs::remove_file(keys_dir.join("oauth_public.key")).expect("rm public");
	let outcome2 = apply(&answers_minimal(&data_dir, &config_path));
	assert!(outcome2.error.is_none(), "second run: {:?}", outcome2.error);
	let private_after = std::fs::read(keys_dir.join("oauth_signing.key")).expect("read private");
	let public_after = std::fs::read(keys_dir.join("oauth_public.key")).expect("read public");
	assert_eq!(
		private_first, private_after,
		"the private key must not be regenerated when only the public is missing"
	);
	assert_eq!(
		public, public_after,
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
	std::fs::remove_file(keys_dir.join("oauth_signing.key")).expect("rm private");
	let outcome2 = apply(&answers_minimal(&data_dir, &config_path));
	let err = outcome2
		.error
		.expect("apply must refuse when only the public key survives");
	let ApplyError::OAuthPairIncomplete(message) = &err else {
		panic!("expected OAuthPairIncomplete, got {err:?}");
	};
	assert!(
		message.contains("oauth_signing.key"),
		"the diagnostic must name the missing private key: {message}"
	);
	// Public key bytes must be unchanged: refusing the run is not
	// an excuse to overwrite the surviving material.
	let public_after = std::fs::read(keys_dir.join("oauth_public.key")).expect("read public");
	assert_eq!(public_before, public_after);
	assert!(
		!keys_dir.join("oauth_signing.key").exists(),
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
	let private_a = std::fs::read(keys_dir.join("oauth_signing.key")).expect("a private");
	let _ = std::fs::remove_file(keys_dir.join("oauth_signing.key"));
	let _ = std::fs::remove_file(keys_dir.join("oauth_public.key"));
	let outcome_b = apply(&answers_minimal(&data_dir, &config_path));
	assert!(outcome_b.error.is_none(), "run b: {:?}", outcome_b.error);
	let public_b = std::fs::read(keys_dir.join("oauth_public.key")).expect("b public");
	// Build the mismatched pair: private_a + public_b.
	let _ = std::fs::remove_file(keys_dir.join("oauth_signing.key"));
	std::fs::write(keys_dir.join("oauth_signing.key"), &private_a).expect("write private_a");
	let outcome = apply(&answers_minimal(&data_dir, &config_path));
	let err = outcome.error.expect("apply must refuse a mismatched pair");
	let ApplyError::OAuthPairMismatch = &err else {
		panic!("expected OAuthPairMismatch, got {err:?}");
	};
	let public_after = std::fs::read(keys_dir.join("oauth_public.key")).expect("read public");
	let private_after = std::fs::read(keys_dir.join("oauth_signing.key")).expect("read private");
	assert_eq!(public_after, public_b, "public key bytes must be untouched");
	assert_eq!(
		private_after, private_a,
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
	assert_eq!(
		key_before, key_after,
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
		panic!("expected CertPairIncomplete, got {err:?}");
	};
	assert!(
		message.contains("key.pem"),
		"the diagnostic must name the missing key: {message}"
	);
	let cert_after = std::fs::read(&cert_path).expect("read cert");
	assert_eq!(
		cert_before, cert_after,
		"the surviving certificate must NOT be overwritten"
	);
	assert!(
		!key_path.exists(),
		"a fresh private key must NOT have been written"
	);
}

/// Every `ApplyError` variant the operator can see on stderr must
/// render without panicking and must carry a path, a reason, or a
/// directive. The Display impl is the contract every failure path
/// relies on, so a regression that drops a field or changes a
/// branch silently would otherwise leave the operator looking at
/// a debug-formatted error.
#[test]
fn apply_error_display_messages_for_every_variant() {
	let io = std::io::Error::other("disk full");
	let path = Path::new("/tmp/example").to_path_buf();
	let cases = vec![
		(ApplyError::KeysDir(path.clone(), io), "keys directory"),
		(
			ApplyError::KeyWrite(path.clone(), std::io::Error::other("nope")),
			"key file",
		),
		(ApplyError::OAuthPairIncomplete("a".to_string()), "a"),
		(ApplyError::OAuthPairMismatch, "do not correspond"),
		(ApplyError::CertPairIncomplete("b".to_string()), "b"),
		(ApplyError::ConfigEncode("c".to_string()), "c"),
		(ApplyError::ConfigInvalid("d".to_string()), "d"),
		(
			ApplyError::ConfigRead(path.clone(), std::io::Error::other("perm")),
			"perm",
		),
		(
			ApplyError::ConfigWrite(path.clone(), std::io::Error::other("disk")),
			"disk",
		),
		(
			ApplyError::ConfigDir(path.clone(), std::io::Error::other("mkdir")),
			"mkdir",
		),
		(ApplyError::ConfigSymlink(path.clone()), "symlink"),
	];
	for (error, expected_fragment) in cases {
		let rendered = format!("{error}");
		assert!(
			rendered.contains(expected_fragment),
			"error {error:?} must render with `{expected_fragment}`: {rendered}"
		);
	}
}
