//! Apply unit tests: the existing-config-that-differs behaviour.
//!
//! Lives in a sibling because the main `apply_tests.rs` and
//! `apply_tests_b.rs` / `apply_tests_c.rs` are at the per-file line
//! limit. These tests pin what happens when an existing config on
//! disk already has the operator's hand-written keys and init
//! needs to merge the desired config on top.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use super::*;
use crate::cli::init::answers::{Mode, Services};

fn answers_minimal() -> Answers {
	Answers {
		mode: Mode::Manual,
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
fn plan_says_update_with_key_count_when_config_differs() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let existing = format!(
		"hostname = \"mail.example.org\"\n\
		 data_dir = \"{}\"\n\
		 domains = [\"example.org\"]\n\
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
	let plan = plan(&answers).expect("plan");
	let config_step = plan
		.steps
		.iter()
		.find_map(|s| match s {
			PlanStep::Config {
				identical,
				file_exists,
				count,
				..
			} => Some((*identical, *file_exists, *count)),
			_ => None,
		})
		.expect("plan must list a Config step");
	assert!(
		!config_step.0,
		"plan must not mark the existing config as identical when an unknown key is present"
	);
	assert!(
		config_step.1,
		"plan must record that the config file already exists"
	);
	assert!(
		config_step.2 >= 6,
		"plan must report at least the six always-managed keys, got {}",
		config_step.2
	);
	let mut rendered = String::new();
	plan.write_to(&mut rendered).expect("render");
	assert!(
		rendered.contains("config: update"),
		"plan must say update for an existing config that differs; rendered: {rendered}"
	);
	assert!(
		rendered.contains(&format!("{} keys", config_step.2)),
		"plan must include the managed-key count; rendered: {rendered}"
	);
}

#[test]
fn apply_rewrites_managed_keys_and_preserves_unknown_ones() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let existing = format!(
		"hostname = \"mail.example.org\"\n\
		 data_dir = \"{}\"\n\
		 domains = [\"example.org\"]\n\
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
	let merged = std::fs::read_to_string(&config_path).expect("read merged");
	assert!(
		merged.contains("srs_secret"),
		"unknown top-level key must survive the rewrite: {merged}"
	);
	assert!(
		merged.contains("dkim"),
		"managed dkim block must be written into the existing config: {merged}"
	);
	assert!(
		merged.contains("tls"),
		"managed tls block must be written into the existing config: {merged}"
	);
	assert!(
		outcome
			.report
			.steps
			.iter()
			.any(|s| matches!(s, ReportStep::Updated(p) if p == &config_path)),
		"report must record the config as updated: {:?}",
		outcome.report.steps
	);
}

#[test]
fn plan_fails_when_existing_config_is_not_valid_toml() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	std::fs::create_dir(&data_dir).expect("mkdir data");
	std::fs::write(&config_path, "this is not = valid TOML\tbroken\n")
		.expect("write unparseable config");
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
			.expect("chmod");
	}
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let err = plan(&answers).expect_err("plan must surface the parse failure");
	assert!(
		matches!(err, ApplyError::ConfigRead(_, _)),
		"expected ConfigRead, got {err:?}"
	);
	assert!(
		format!("{err}").contains("read"),
		"ConfigRead display must name the operation"
	);
}
