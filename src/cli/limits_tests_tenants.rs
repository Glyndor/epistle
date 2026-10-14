//! Per-tenant submission limit editing through `epistle limits
//! set submission-rate --tenant NAME`. Mirrors the per-domain tests
//! in `limits_tests_domains.rs` so the operator workflow, the config
//! shape and the restart pipeline all stay aligned.

use std::io::{Seek, Write};

use super::*;
use crate::config::{Config, Tenant};

pub(super) fn tenant_config_file() -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir_in(".").unwrap();
	let mut file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\n\
		 domains = [\"example.org\"]\n\n\
		 [[tenant]]\nname = \"acme\"\ndomains = [\"example.org\"]\n",
		dir.path().canonicalize().unwrap().to_string_lossy()
	)
	.unwrap();
	(dir, file)
}

#[test]
fn tenant_submission_rate_set_unset_round_trip() {
	let (_dir, file) = tenant_config_file();
	let original = std::fs::read_to_string(file.path()).unwrap();
	let doc = edit_document(
		file.path(),
		Key::SubmissionRate,
		None,
		Some("acme"),
		Some("120"),
	)
	.expect("set tenant submission-rate");
	assert_eq!(
		doc.commit().unwrap(),
		super::super::config_edit::Outcome::Changed
	);
	let config: Config =
		Config::parse_text(&std::fs::read_to_string(file.path()).unwrap(), file.path())
			.expect("config");
	assert_eq!(config.tenants.len(), 1);
	assert_eq!(config.tenants[0].submission_rate_limit_per_min, Some(120));
	let doc = edit_document(file.path(), Key::SubmissionRate, None, Some("acme"), None)
		.expect("unset tenant submission-rate");
	assert_eq!(
		doc.commit().unwrap(),
		super::super::config_edit::Outcome::Changed
	);
	let config: Config =
		Config::parse_text(&std::fs::read_to_string(file.path()).unwrap(), file.path())
			.expect("config");
	assert_eq!(config.tenants[0].submission_rate_limit_per_min, None);
	let now: toml::Value = toml::from_str(&std::fs::read_to_string(file.path()).unwrap()).unwrap();
	let before: toml::Value = toml::from_str(&original).unwrap();
	assert_eq!(now, before, "set then unset leaves the config as it was");
}

#[test]
fn tenant_command_refuses_unknown_tenant_name() {
	let (_dir, file) = tenant_config_file();
	assert_eq!(
		edit_document(
			file.path(),
			Key::SubmissionRate,
			None,
			Some("missing"),
			Some("100"),
		)
		.err()
		.as_deref(),
		Some("tenant \"missing\" not found in config")
	);
}

#[test]
fn tenant_command_refuses_combined_domain_and_tenant() {
	let (_dir, file) = tenant_config_file();
	assert_eq!(
		edit_document(
			file.path(),
			Key::SubmissionRate,
			Some("example.org"),
			Some("acme"),
			Some("100"),
		)
		.err()
		.as_deref(),
		Some("--domain and --tenant cannot be combined")
	);
}

#[test]
fn tenant_command_only_accepts_submission_rate_for_now() {
	let (_dir, file) = tenant_config_file();
	assert_eq!(
		edit_document(file.path(), Key::Quota, None, Some("acme"), Some("10G"))
			.err()
			.as_deref(),
		Some("per-tenant limits support submission-rate only")
	);
}

#[test]
fn tenant_submission_rate_round_trip_preserves_the_other_tenant_fields() {
	let (_dir, file) = tenant_config_file();
	let mut text = std::fs::read_to_string(file.path()).unwrap();
	text.push_str("quota_bytes = 1048576\nmax_accounts = 7\n");
	let mut file_handle = file.as_file();
	file_handle.set_len(0).unwrap();
	file_handle.rewind().unwrap();
	file_handle.write_all(text.as_bytes()).unwrap();
	edit_document(
		file.path(),
		Key::SubmissionRate,
		None,
		Some("acme"),
		Some("200"),
	)
	.expect("set submission-rate")
	.commit()
	.expect("commit");
	let config: Config =
		Config::parse_text(&std::fs::read_to_string(file.path()).unwrap(), file.path())
			.expect("config");
	assert_eq!(config.tenants.len(), 1);
	let tenant: &Tenant = &config.tenants[0];
	assert_eq!(tenant.name.as_deref(), Some("acme"));
	assert_eq!(tenant.submission_rate_limit_per_min, Some(200));
	assert_eq!(tenant.quota_bytes, Some(1048576));
	assert_eq!(tenant.max_accounts, Some(7));
}
