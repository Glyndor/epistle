//! Apply unit tests: the existing-config-that-differs behaviour.
//!
//! Lives in a sibling because the main `apply_tests.rs` and
//! `apply_tests_b.rs` / `apply_tests_c.rs` are at the per-file line
//! limit. These tests pin what happens when an existing config on
//! disk already has the operator's hand-written keys and init
//! needs to merge the desired config on top.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use super::tests_failures::apply_error_name;
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
		image: None,
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
	// The merged config carries the inline `srs_secret` fixture.
	// The contract assertions must not echo the full file: if
	// the rewrite drops the dkim or tls block, the panic would
	// dump the SRS secret into the CI log alongside the
	// diagnosis. The booleans capture the check; the messages
	// name the missing block only.
	let has_srs = merged.contains("srs_secret");
	let has_dkim = merged.contains("dkim");
	let has_tls = merged.contains("tls");
	assert!(
		has_srs,
		"unknown top-level key must survive the rewrite"
	);
	assert!(
		has_dkim,
		"managed dkim block must be written into the existing config"
	);
	assert!(
		has_tls,
		"managed tls block must be written into the existing config"
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
		"expected ConfigRead, got {}",
		apply_error_name(&err)
	);
	assert!(
		format!("{err}").contains("read"),
		"ConfigRead display must name the operation"
	);
}

/// Re-running `epistle init` with `services.database = true` against
/// a config that already carries an operator-curated `[database]`
/// table must not clobber the operator's keys. The apply phase
/// owns `url` and `password_file` (the two keys it is the source
/// of truth for) and preserves every other field the operator
/// has added, here `directory = true` and a custom
/// `max_connections`. The previous shape wiped the whole table
/// on the rewrite, which silently dropped operator tuning.
#[test]
fn apply_preserves_operator_keys_inside_the_database_table() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	std::fs::create_dir_all(&data_dir).expect("mkdir data");
	// A valid `mail.toml` with an operator-curated `[database]`
	// table. The apply phase will lay down the `url` and
	// `password_file` keys; `directory` and `max_connections`
	// must survive.
	let existing = format!(
		"hostname = \"mail.example.org\"\n\
		 data_dir = \"{}\"\n\
		 domains = [\"example.org\"]\n\n\
		 [database]\n\
		 url = \"postgres://epistle@%2Frun%2Fpostgresql/epistle\"\n\
		 directory = true\n\
		 max_connections = 32\n",
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
	answers.services.database = true;
	let outcome = apply(&answers);
	assert!(outcome.error.is_none(), "apply failed: {:?}", outcome.error);
	let merged = std::fs::read_to_string(&config_path).expect("read merged");
	// The two managed keys made it in (the password_file is the
	// one the apply phase just wrote).
	assert!(
		merged.contains("password_file"),
		"managed password_file must be written on a re-run with database = true: {merged}"
	);
	// The operator's `directory` and `max_connections` survive.
	assert!(
		merged.contains("directory = true"),
		"operator's `directory = true` must survive the re-run: {merged}"
	);
	assert!(
		merged.contains("max_connections = 32"),
		"operator's `max_connections = 32` must survive the re-run: {merged}"
	);
}

/// Re-running with `services.database = false` against a config
/// that carries an operator-curated `[database]` table must leave
/// the table untouched: the operator may run their own
/// PostgreSQL outside the stack and the apply phase has no
/// reason to wipe the section. The previous shape listed
/// `[database]` in `DROP_WHEN_NOT_IN_DESIRED` and silently
/// removed the whole table on every `database = false` re-run,
/// losing `directory`, `max_connections`, and any future field
/// the operator added. The new shape keeps the table verbatim:
/// the desired config has no `[database]` key, so the
/// reconciliation passes through and the existing table
/// survives.
#[test]
fn apply_keeps_the_database_table_when_services_database_is_false() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	std::fs::create_dir_all(&data_dir).expect("mkdir data");
	let existing = format!(
		"hostname = \"mail.example.org\"\n\
		 data_dir = \"{}\"\n\
		 domains = [\"example.org\"]\n\n\
		 [database]\n\
		 url = \"postgres://epistle@%2Frun%2Fpostgresql/epistle\"\n\
		 directory = true\n\
		 max_connections = 32\n",
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
	answers.services.database = false;
	let outcome = apply(&answers);
	assert!(outcome.error.is_none(), "apply failed: {:?}", outcome.error);
	let merged = std::fs::read_to_string(&config_path).expect("read merged");
	assert!(
		merged.contains("[database]"),
		"a re-run with services.database = false must keep the [database] table: {merged}"
	);
	assert!(
		merged.contains("directory = true"),
		"the operator's `directory = true` must survive a database = false re-run: {merged}"
	);
	assert!(
		merged.contains("max_connections = 32"),
		"the operator's `max_connections = 32` must survive a database = false re-run: {merged}"
	);
}
