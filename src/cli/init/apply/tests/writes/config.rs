//! What the apply phase puts on disk: the keys it writes, the config it
//! merges and the fact that it leaves the files it did not touch alone.

use super::super::helpers::answers::{answers_minimal, file_mtime, sha256_of};
use super::super::helpers::errors::apply_error_name;
use super::*;
use crate::cli::init::answers::Services;

#[test]
fn apply_writes_keys_and_config() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let outcome = apply(&answers);
	assert!(outcome.error.is_none(), "apply failed: {:?}", outcome.error);
	let report = outcome.report;
	let s1 = data_dir.join("keys/s1.pem");
	let s2 = data_dir.join("keys/s2.pem");
	let storage = dir.path().join("secrets/storage.key");
	let oauth_private = dir.path().join("secrets/oauth_signing.key");
	let oauth_public = data_dir.join("keys/oauth_public.key");
	assert!(s1.exists());
	assert!(storage.exists());
	assert!(oauth_private.exists());
	assert!(oauth_public.exists());
	assert!(s2.exists(), "the RSA key is made in process, always");
	assert!(config_path.exists());
	assert!(
		report
			.steps
			.iter()
			.any(|s| matches!(s, ReportStep::Wrote(_))),
		"expected at least one write, got {report:?}"
	);
}

#[test]
fn apply_does_not_rewrite_keys_when_every_answer_changes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let outcome = apply(&answers);
	assert!(
		outcome.error.is_none(),
		"first apply failed: {:?}",
		outcome.error
	);
	drop(outcome);
	let s1 = data_dir.join("keys/s1.pem");
	let s2 = data_dir.join("keys/s2.pem");
	let storage = dir.path().join("secrets/storage.key");
	let oauth_private = dir.path().join("secrets/oauth_signing.key");
	let oauth_public = data_dir.join("keys/oauth_public.key");
	let before = [
		sha256_of(&s1).expect("s1"),
		sha256_of(&storage).expect("storage"),
		sha256_of(&oauth_private).expect("oauth_private"),
		sha256_of(&oauth_public).expect("oauth_public"),
	];
	let before_s2 = sha256_of(&s2).expect("s2");
	answers.hostname = "mail2.example.org".to_string();
	answers.domains = vec!["example.org".to_string(), "example.com".to_string()];
	// Toggle services that need no extra config sections so the second
	// apply still validates; the test's job is to confirm keys survive
	// every answer change, not to test service-specific config branches.
	answers.services = Services {
		antivirus: None,
		imap: false,
		submission: true,
		pop3: false,
		managesieve: false,
		webdav: false,
		api: false,
		database: false,
		certs: false,
	};
	answers.mode = crate::cli::init::answers::Mode::Manual;
	let outcome = apply(&answers);
	assert!(
		outcome.error.is_none(),
		"second apply failed: {:?}",
		outcome.error
	);
	drop(outcome);
	let after = [
		sha256_of(&s1).expect("s1"),
		sha256_of(&storage).expect("storage"),
		sha256_of(&oauth_private).expect("oauth_private"),
		sha256_of(&oauth_public).expect("oauth_public"),
	];
	assert_eq!(
		before, after,
		"keys must not be regenerated when answers change"
	);
	assert_eq!(before_s2, sha256_of(&s2).expect("s2"));
}

#[test]
fn apply_is_idempotent() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let outcome = apply(&answers);
	assert!(
		outcome.error.is_none(),
		"first apply failed: {:?}",
		outcome.error
	);
	drop(outcome);
	let config_mtime_before = file_mtime(&config_path);
	let s1 = data_dir.join("keys/s1.pem");
	let s1_mtime_before = file_mtime(&s1);
	let outcome = apply(&answers);
	assert!(
		outcome.error.is_none(),
		"second apply failed: {:?}",
		outcome.error
	);
	drop(outcome);
	let config_mtime_after = file_mtime(&config_path);
	let s1_mtime_after = file_mtime(&s1);
	assert_eq!(config_mtime_before, config_mtime_after);
	assert_eq!(s1_mtime_before, s1_mtime_after);
}

#[test]
fn apply_does_not_validate_a_bad_candidate_config() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let outcome = apply(&answers);
	assert!(
		outcome.error.is_none(),
		"first apply failed: {:?}",
		outcome.error
	);
	drop(outcome);
	let before = std::fs::read(&config_path).expect("read config");
	let before_mtime = file_mtime(&config_path);
	answers.hostname = "localhost".to_string();
	let outcome = apply(&answers);
	let err = outcome
		.error
		.expect("expected ConfigInvalid, apply succeeded");
	if let ApplyError::ConfigInvalid(_) = err {
		let after_mtime = file_mtime(&config_path);
		assert_eq!(before_mtime, after_mtime);
		let after = std::fs::read(&config_path).expect("read config");
		assert_eq!(before, after);
	} else {
		panic!("expected ConfigInvalid, got {}", apply_error_name(&err));
	}
}

#[test]
fn apply_preserves_unknown_top_level_keys() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let existing = format!(
		"hostname = \"mail.example.org\"\n\
		 data_dir = \"{}\"\n\
		 domains = [\"example.org\"]\n\
		 greylist_delay_secs = 0\n\
		 dnsbl_zones = []\n\
		 dnsbl_domain_zones = []\n\
		 dnsbl_url_zones = []\n\
		 first_time_sender_delay_secs = 0\n\
		 masked_addresses_max = 0\n\
		 srs_secret = \"keep-me\"\n",
		data_dir.display(),
	);
	std::fs::write(&config_path, existing).expect("write existing config");
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
			.expect("chmod");
	}
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let outcome = apply(&answers);
	assert!(outcome.error.is_none(), "apply failed: {:?}", outcome.error);
	drop(outcome);
	let merged = std::fs::read_to_string(&config_path).expect("read merged");
	// The merged file carries the inline `srs_secret = "keep-me"`
	// fixture. A panic that interpolated the full file would
	// dump the SRS secret into the CI log; a boolean captures
	// the contract without echoing the file.
	let has_srs = merged.contains("srs_secret");
	assert!(
		has_srs,
		"unknown top-level key srs_secret must be preserved"
	);
}
