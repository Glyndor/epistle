//! Tests for the `epistle app-password` commands.

use super::*;
use crate::directory_store::AppPasswordStore;

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

	// Create prints the secret once.
	let mut out = Vec::new();
	assert_eq!(
		create(&config, "alice", "phone", None, None, &mut out),
		ExitCode::SUCCESS
	);
	let created = String::from_utf8(out).expect("utf8");
	assert!(created.contains("secret (shown once):"));

	// The store now holds one entry.
	assert_eq!(
		AppPasswordStore::open(dir.path())
			.expect("open")
			.for_account("alice")
			.len(),
		1
	);

	// List shows the label but not the secret.
	let mut out = Vec::new();
	assert_eq!(list(&config, &mut out), ExitCode::SUCCESS);
	let listed = String::from_utf8(out).expect("utf8");
	assert!(listed.contains("alice"));
	assert!(listed.contains("phone"));
	assert!(!listed.contains("secret"));

	// Revoke removes it.
	let mut out = Vec::new();
	assert_eq!(
		revoke(&config, "alice", "phone", &mut out),
		ExitCode::SUCCESS
	);
	assert_eq!(
		AppPasswordStore::open(dir.path())
			.expect("open")
			.for_account("alice")
			.len(),
		0
	);
}

#[test]
fn create_with_expiry_and_cidr_is_stored() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let mut out = Vec::new();
	assert_eq!(
		create(
			&config,
			"alice",
			"phone",
			Some(9999),
			Some("203.0.113.0/24".to_string()),
			&mut out,
		),
		ExitCode::SUCCESS
	);
	let store = AppPasswordStore::open(dir.path()).expect("open");
	let entry = &store.for_account("alice")[0];
	assert_eq!(entry.expires_at, Some(9999));
	assert_eq!(entry.ip_cidr.as_deref(), Some("203.0.113.0/24"));
}

#[test]
fn create_rejects_bad_cidr() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let mut out = Vec::new();
	assert_eq!(
		create(
			&config,
			"alice",
			"phone",
			None,
			Some("not-a-cidr".to_string()),
			&mut out,
		),
		ExitCode::FAILURE
	);
}

#[test]
fn revoke_missing_label_fails() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let mut out = Vec::new();
	assert_eq!(
		revoke(&config, "alice", "absent", &mut out),
		ExitCode::FAILURE
	);
}
