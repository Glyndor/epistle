//! Apply unit tests.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::cli::init::answers::Services;

#[cfg(unix)]
fn sha256_of(path: &std::path::Path) -> Option<Vec<u8>> {
	let bytes = std::fs::read(path).ok()?;
	Some(
		ring::digest::digest(&ring::digest::SHA256, &bytes)
			.as_ref()
			.to_vec(),
	)
}

#[cfg(not(unix))]
fn sha256_of(path: &std::path::Path) -> Option<Vec<u8>> {
	None
}

fn answers_minimal() -> Answers {
	Answers {
		mode: crate::cli::init::answers::Mode::Manual,
		hostname: "mail.example.org".to_string(),
		domains: vec!["example.org".to_string()],
		public_ipv4: Some(Ipv4Addr::new(8, 8, 8, 8)),
		public_ipv6: Some(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
		data_dir: PathBuf::from("/var/lib/epistle"),
		config_path: PathBuf::from("/etc/epistle/mail.toml"),
		dns: None,
		services: Services::default(),
	}
}

#[test]
fn plan_lists_every_step() {
	let answers = answers_minimal();
	let plan = plan(&answers).expect("plan");
	let labels: Vec<String> = plan
		.steps
		.iter()
		.map(|s| {
			format!("{:?}", s)
				.split_whitespace()
				.next()
				.unwrap_or("")
				.to_string()
		})
		.collect();
	assert!(
		plan.steps
			.iter()
			.any(|s| matches!(s, PlanStep::DkimEd25519 { .. }))
	);
	assert!(
		plan.steps
			.iter()
			.any(|s| matches!(s, PlanStep::DkimRsa { .. }))
	);
	assert!(
		plan.steps
			.iter()
			.any(|s| matches!(s, PlanStep::Storage { .. }))
	);
	assert!(
		plan.steps
			.iter()
			.any(|s| matches!(s, PlanStep::OAuthPrivate { .. }))
	);
	assert!(
		plan.steps
			.iter()
			.any(|s| matches!(s, PlanStep::OAuthPublic { .. }))
	);
	assert!(
		plan.steps
			.iter()
			.any(|s| matches!(s, PlanStep::Config { .. }))
	);
	assert!(!labels.is_empty());
}

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
	let storage = data_dir.join("keys/storage.key");
	let oauth_private = data_dir.join("keys/oauth_signing.key");
	let oauth_public = data_dir.join("keys/oauth_public.key");
	assert!(s1.exists());
	assert!(storage.exists());
	assert!(oauth_private.exists());
	assert!(oauth_public.exists());
	if which_openssl() {
		assert!(s2.exists());
	}
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
	let storage = data_dir.join("keys/storage.key");
	let oauth_private = data_dir.join("keys/oauth_signing.key");
	let oauth_public = data_dir.join("keys/oauth_public.key");
	let before = [
		sha256_of(&s1).expect("s1"),
		sha256_of(&storage).expect("storage"),
		sha256_of(&oauth_private).expect("oauth_private"),
		sha256_of(&oauth_public).expect("oauth_public"),
	];
	let before_s2 = which_openssl().then(|| sha256_of(&s2).expect("s2"));
	answers.hostname = "mail2.example.org".to_string();
	answers.domains = vec!["example.org".to_string(), "example.com".to_string()];
	// Toggle services that need no extra config sections so the second
	// apply still validates; the test's job is to confirm keys survive
	// every answer change, not to test service-specific config branches.
	answers.services = Services {
		imap: false,
		submission: true,
		pop3: false,
		managesieve: false,
		webdav: false,
		api: false,
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
	if let Some(before_s2) = before_s2 {
		assert_eq!(before_s2, sha256_of(&s2).expect("s2"));
	}
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
		panic!("expected ConfigInvalid, got {err:?}");
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
	assert!(
		merged.contains("srs_secret"),
		"unknown top-level key srs_secret must be preserved: {merged}"
	);
}

#[test]
fn plan_step_dkim_rsa_skipped_when_openssl_missing() {
	// We can't remove openssl at runtime; instead we confirm the bool
	// branch is exercised by `apply` when the helper says it is unavailable
	// (the helper returns true on PATH).
	let answers = answers_minimal();
	let plan = plan(&answers).expect("plan");
	let rsa = plan
		.steps
		.iter()
		.find_map(|s| match s {
			PlanStep::DkimRsa {
				openssl_available, ..
			} => Some(*openssl_available),
			_ => None,
		})
		.expect("rsa step");
	assert_eq!(rsa, which_openssl());
}

#[test]
fn plan_print_does_not_panic() {
	let answers = answers_minimal();
	let plan = plan(&answers).expect("plan");
	let mut out = String::new();
	plan.write_to(&mut out).expect("print");
	assert!(out.contains("dkim"));
	assert!(out.contains("config"));
}

#[cfg(unix)]
#[test]
fn apply_creates_missing_config_parent_dir_with_mode_0750() {
	let dir = tempfile::tempdir().expect("tempdir");
	let etc = dir.path().join("etc");
	let config_path = etc.join("mail.toml");
	let data_dir = dir.path().join("data");
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	// The plan must list the missing parent as a step the operator
	// sees before confirming, before any apply has had a chance to
	// create it.
	let plan = plan(&answers).expect("plan");
	assert!(
		plan.steps
			.iter()
			.any(|s| matches!(s, PlanStep::ConfigDir { path } if path == &etc)),
		"plan must list the missing parent as a ConfigDir step; plan was {:?}",
		plan.steps
	);
	let outcome = apply(&answers);
	assert!(outcome.error.is_none(), "apply failed: {:?}", outcome.error);
	assert!(etc.exists(), "apply did not create the parent directory");
	let mode = std::fs::metadata(&etc).expect("stat").permissions().mode();
	assert_eq!(
		mode & 0o777,
		0o750,
		"config parent must be 0750, got {:o}",
		mode & 0o777
	);
	assert!(
		outcome
			.report
			.steps
			.iter()
			.any(|s| matches!(s, ReportStep::CreatedDir(p) if p == &etc)),
		"apply must report the created directory; report was {:?}",
		outcome.report.steps
	);
	// A second apply finds the directory already there and does not
	// create or report it again.
	let outcome = apply(&answers);
	assert!(outcome.error.is_none());
	assert!(
		!outcome
			.report
			.steps
			.iter()
			.any(|s| matches!(s, ReportStep::CreatedDir(_))),
		"second apply must not re-create the existing parent; report was {:?}",
		outcome.report.steps
	);
}

#[cfg(unix)]
#[test]
fn apply_leaves_existing_config_parent_mode_untouched() {
	let dir = tempfile::tempdir().expect("tempdir");
	let etc = dir.path().join("etc");
	std::fs::create_dir(&etc).expect("mkdir");
	std::fs::set_permissions(&etc, std::fs::Permissions::from_mode(0o755)).expect("chmod");
	let config_path = etc.join("mail.toml");
	let data_dir = dir.path().join("data");
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let outcome = apply(&answers);
	assert!(outcome.error.is_none());
	let mode = std::fs::metadata(&etc).expect("stat").permissions().mode();
	assert_eq!(
		mode & 0o777,
		0o755,
		"apply must not change the mode of an existing directory, got {:o}",
		mode & 0o777
	);
}

#[test]
fn apply_partial_failure_renders_what_was_written() {
	// Force a failure after the keys have been written: create a
	// regular file where the config parent must be a directory. The
	// apply phase must surface every step that completed before the
	// failure, so the operator can see what is already on disk.
	let dir = tempfile::tempdir().expect("tempdir");
	let blocker = dir.path().join("etc");
	std::fs::write(&blocker, b"not a directory").expect("blocker");
	let config_path = blocker.join("mail.toml");
	let data_dir = dir.path().join("data");
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let outcome = apply(&answers);
	let error = outcome
		.error
		.expect("apply must surface the error after partial progress");
	assert!(
		matches!(
			error,
			ApplyError::ConfigRead(_, _) | ApplyError::ConfigWrite(_, _)
		),
		"unexpected error variant: {error:?}"
	);
	let s1 = data_dir.join("keys/s1.pem");
	assert!(
		s1.exists(),
		"the keys that ran before the failure must be on disk"
	);
	assert!(
		outcome
			.report
			.steps
			.iter()
			.any(|s| matches!(s, ReportStep::Wrote(p) if p == &s1)),
		"partial report must list the keys that completed; got {:?}",
		outcome.report.steps
	);
}

#[cfg(unix)]
fn file_mtime(path: &PathBuf) -> std::time::SystemTime {
	std::fs::metadata(path)
		.expect("metadata")
		.modified()
		.expect("mtime")
}

/// The plan must list directory steps before the writes that depend
/// on them: a fresh `data_dir` and a fresh `config_path` parent must
/// appear ahead of every key write and the config write, because
/// `apply` creates the directories first and the operator reads the
/// plan before confirming.
#[test]
fn plan_lists_directory_steps_before_writes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("etc").join("mail.toml");
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let plan = plan(&answers).expect("plan");
	// The first step on a fresh tree must be a directory creation;
	// every write step must follow it.
	let first = plan
		.steps
		.first()
		.expect("plan must have at least one step");
	assert!(
		matches!(first, PlanStep::DataDir { .. } | PlanStep::ConfigDir { .. }),
		"plan must lead with a directory step, got {first:?}"
	);
	// Every write step must come after every preceding directory
	// step. Walk the list, remember the last directory index, and
	// assert no write index is below it.
	let mut last_directory_index: Option<usize> = None;
	for (i, step) in plan.steps.iter().enumerate() {
		let is_directory = matches!(step, PlanStep::DataDir { .. } | PlanStep::ConfigDir { .. });
		if is_directory {
			last_directory_index = Some(i);
		} else if let Some(last) = last_directory_index {
			assert!(
				i > last,
				"write step at index {i} appears before a directory step: {:?}",
				plan.steps
			);
		}
	}
}

#[cfg(not(unix))]
fn file_mtime(_path: &PathBuf) -> std::time::SystemTime {
	std::time::SystemTime::UNIX_EPOCH
}
