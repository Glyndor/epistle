//! Tests for the `epistle api-key` commands.

use super::*;
use crate::api::ApiKeyStore;

fn config(data_dir: &std::path::Path) -> Config {
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
		data_dir.display()
	);
	toml::from_str(&toml).expect("config parses")
}

fn read_scope() -> Vec<String> {
	vec!["read".to_string()]
}

#[test]
fn create_list_revoke_roundtrip() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());

	let mut out = Vec::new();
	assert_eq!(
		create(
			&config,
			NewKey {
				label: "ci".to_string(),
				expires_at: None,
				ip_cidr: None,
				scopes: read_scope(),
				domains: Vec::new(),
				account: None,
				class: None,
			},
			false,
			&mut out,
			&mut Vec::new()
		),
		ExitCode::SUCCESS
	);
	let created = String::from_utf8(out).expect("utf8");
	assert!(created.contains("key (shown once):"));

	assert_eq!(ApiKeyStore::open(dir.path()).expect("open").keys().len(), 1);

	let mut out = Vec::new();
	assert_eq!(
		list(&config, false, &mut out, &mut Vec::new()),
		ExitCode::SUCCESS
	);
	let listed = String::from_utf8(out).expect("utf8");
	assert!(listed.contains("ci"));
	assert!(listed.contains("scopes=read"), "{listed}");
	assert!(!listed.contains("key"));

	let mut out = Vec::new();
	assert_eq!(
		revoke(&config, "ci", true, false, &mut out),
		ExitCode::SUCCESS
	);
	assert_eq!(ApiKeyStore::open(dir.path()).expect("open").keys().len(), 0);
}

#[test]
fn create_with_expiry_and_cidr_is_stored() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let mut out = Vec::new();
	assert_eq!(
		create(
			&config,
			NewKey {
				label: "ci".to_string(),
				expires_at: Some(9999),
				ip_cidr: Some("10.0.0.0/8".to_string()),
				scopes: read_scope(),
				domains: Vec::new(),
				account: None,
				class: None,
			},
			false,
			&mut out,
			&mut Vec::new()
		),
		ExitCode::SUCCESS
	);
	let store = ApiKeyStore::open(dir.path()).expect("open");
	let key = &store.keys()[0];
	assert_eq!(key.expires_at, Some(9999));
	assert_eq!(key.ip_cidr.as_deref(), Some("10.0.0.0/8"));
}

/// `--scope` is required: an unscoped key would be admin-equivalent on
/// first leak, which is exactly the failure mode scopes exist to prevent.
#[test]
fn create_without_scope_is_rejected() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let mut out = Vec::new();
	assert_eq!(
		create(
			&config,
			NewKey {
				label: "ci".to_string(),
				expires_at: None,
				ip_cidr: None,
				scopes: Vec::new(),
				domains: Vec::new(),
				account: None,
				class: None,
			},
			false,
			&mut out,
			&mut Vec::new()
		),
		ExitCode::from(2),
		"--scope must be required"
	);
}

#[test]
fn create_rejects_bad_cidr() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let mut out = Vec::new();
	assert_eq!(
		create(
			&config,
			NewKey {
				label: "ci".to_string(),
				expires_at: None,
				ip_cidr: Some("bogus".to_string()),
				scopes: read_scope(),
				domains: Vec::new(),
				account: None,
				class: None,
			},
			false,
			&mut out,
			&mut Vec::new()
		),
		ExitCode::from(2)
	);
}

#[test]
fn parse_scope_rejects_unknown_values() {
	assert!(parse_scope("read").is_ok());
	assert!(parse_scope("write").is_ok());
	assert!(parse_scope("send").is_ok());
	assert!(parse_scope("admin").is_err());
	assert!(parse_scope("").is_err());
}

#[test]
fn revoke_missing_label_fails() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let mut out = Vec::new();
	assert_eq!(
		revoke(&config, "absent", true, false, &mut out),
		ExitCode::from(2)
	);
}

#[test]
fn a_label_the_rule_refuses_creates_no_key() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	for label in ["", "  ", "ci\nprod", "\u{202e}ci", " ci", &"a".repeat(65)] {
		let code = create(
			&config,
			NewKey {
				label: label.to_string(),
				expires_at: None,
				ip_cidr: None,
				scopes: read_scope(),
				domains: Vec::new(),
				account: None,
				class: None,
			},
			false,
			&mut Vec::new(),
			&mut Vec::new(),
		);
		assert_eq!(
			code,
			ExitCode::from(super::super::exit::REFUSED),
			"{label:?}"
		);
	}
	assert!(
		ApiKeyStore::open(dir.path())
			.expect("open")
			.keys()
			.is_empty()
	);
}
