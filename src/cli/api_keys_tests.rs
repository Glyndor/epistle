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

#[test]
fn create_list_revoke_roundtrip() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());

	let mut out = Vec::new();
	assert_eq!(
		create(&config, "ci", None, None, &mut out),
		ExitCode::SUCCESS
	);
	let created = String::from_utf8(out).expect("utf8");
	assert!(created.contains("key (shown once):"));

	assert_eq!(ApiKeyStore::open(dir.path()).expect("open").keys().len(), 1);

	let mut out = Vec::new();
	assert_eq!(list(&config, &mut out), ExitCode::SUCCESS);
	let listed = String::from_utf8(out).expect("utf8");
	assert!(listed.contains("ci"));
	assert!(!listed.contains("key"));

	let mut out = Vec::new();
	assert_eq!(revoke(&config, "ci", &mut out), ExitCode::SUCCESS);
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
			"ci",
			Some(9999),
			Some("10.0.0.0/8".to_string()),
			&mut out,
		),
		ExitCode::SUCCESS
	);
	let store = ApiKeyStore::open(dir.path()).expect("open");
	let key = &store.keys()[0];
	assert_eq!(key.expires_at, Some(9999));
	assert_eq!(key.ip_cidr.as_deref(), Some("10.0.0.0/8"));
}

#[test]
fn create_rejects_bad_cidr() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let mut out = Vec::new();
	assert_eq!(
		create(&config, "ci", None, Some("bogus".to_string()), &mut out),
		ExitCode::FAILURE
	);
}

#[test]
fn revoke_missing_label_fails() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let mut out = Vec::new();
	assert_eq!(revoke(&config, "absent", &mut out), ExitCode::FAILURE);
}
