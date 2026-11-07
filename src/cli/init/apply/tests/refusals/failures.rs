//! Apply-phase failure scenarios: every case asserts the user-visible
//! outcome, the matching `ApplyError` variant, the steps that ran
//! before the failure, and the rendered report listing those steps in
//! the same shape the operator sees on stderr.

use super::super::helpers::errors::{answers_minimal, apply_error_name, render_report_to_string};
use super::*;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

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
		"expected KeysDir, got {}",
		apply_error_name(&err)
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
		"expected ConfigInvalid, got {}",
		apply_error_name(&err)
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
		"expected ConfigRead or ConfigWrite, got {}",
		apply_error_name(&err)
	);
	let rendered = render_report_to_string(&outcome.report);
	// Every step that ran before the failure must show up in the
	// rendered report with the same shape the operator sees on stderr.
	let keys_dir = data_dir.join("keys");
	assert!(
		rendered.contains("created dir:") && rendered.contains(&data_dir.display().to_string()),
		"data_dir creation missing from rendered report: {rendered}"
	);
	for path in [
		crate::cli::init::host_secrets::storage_key(&data_dir),
		crate::cli::init::host_secrets::oauth_signing_key(&data_dir),
	] {
		assert!(
			path.exists(),
			"a key file written before the failure is missing"
		);
	}
	for name in ["s1.pem", "oauth_public.key", "cert.pem", "key.pem"] {
		let path = keys_dir.join(name);
		assert!(
			path.exists(),
			"a key file written before the failure is missing"
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
	// A directory sits where the storage key should land. A directory
	// is not a key, so apply must try to write the file and the
	// `rename(2)` onto it fails with `EISDIR` (root included, unlike a
	// permission bit). The DKIM ed25519 and RSA keys have already
	// landed on disk when the storage-key write fails, so the apply
	// phase must (1) propagate the failure as `KeyWrite` (no panic),
	// (2) keep every earlier `Wrote` step in the report so the
	// operator sees what landed, and (3) name the storage key path it
	// could not write, not a generic message.
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	std::fs::create_dir_all(crate::cli::init::host_secrets::storage_key(&data_dir))
		.expect("blocker dir");
	let outcome = apply(&answers_minimal(&data_dir, &config_path));
	let err = outcome
		.error
		.expect("apply must surface a KeyWrite error after the obstruction");
	let ApplyError::KeyWrite(path, _io) = &err else {
		panic!("expected KeyWrite, got {}", apply_error_name(&err));
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
		!crate::cli::init::host_secrets::storage_key(&data_dir).is_file(),
		"storage.key must NOT be on disk as a key because the write failed"
	);
}

#[cfg(unix)]
#[test]
fn apply_does_not_leave_a_staging_temp_after_a_failed_write() {
	// The storage-key write fails on a directory at its destination
	// after `write_secret` has already created and filled its staging
	// temp. That temp must not survive the failed apply, and once the
	// obstruction is gone a second run must write the storage key.
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	let blocker = crate::cli::init::host_secrets::storage_key(&data_dir);
	std::fs::create_dir_all(&blocker).expect("blocker dir");
	let outcome = apply(&answers_minimal(&data_dir, &config_path));
	assert!(
		matches!(&outcome.error, Some(ApplyError::KeyWrite(path, _)) if path.ends_with("storage.key")),
		"the obstruction must fail the storage-key write, got {:?}",
		outcome.error.as_ref().map(apply_error_name)
	);
	let leftovers: Vec<String> = std::fs::read_dir(&keys_dir)
		.expect("read keys dir")
		.map(|entry| {
			entry
				.expect("entry")
				.file_name()
				.to_string_lossy()
				.into_owned()
		})
		.filter(|name| name.ends_with(".tmp"))
		.collect();
	assert_eq!(
		leftovers,
		Vec::<String>::new(),
		"a failed key write must not leave a staging temp in keys/"
	);
	std::fs::remove_dir_all(&blocker).expect("remove blocker");
	let outcome2 = apply(&answers_minimal(&data_dir, &config_path));
	assert!(
		outcome2.error.is_none(),
		"retry must succeed: {:?}",
		outcome2.error.as_ref().map(apply_error_name)
	);
	assert!(
		crate::cli::init::host_secrets::storage_key(&data_dir).is_file(),
		"storage.key must be written on retry"
	);
}
