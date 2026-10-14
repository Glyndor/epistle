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

/// Lay down a dynamic account row in `<data_dir>/accounts.toml` so the
/// `create` command's "account must exist" check passes. The password
/// hash is a placeholder; the test path does not authenticate.
fn seed_dynamic_account(data_dir: &std::path::Path, name: &str, address: &str) {
	let path = data_dir.join("accounts.toml");
	std::fs::write(
		&path,
		format!(
			"[[accounts]]\nname = \"{name}\"\naddresses = [\"{address}\"]\npassword_hash = \"stub\"\n"
		),
	)
	.expect("write accounts.toml");
}

#[test]
fn create_list_revoke_roundtrip() {
	let dir = tempfile::tempdir().expect("tempdir");
	seed_dynamic_account(dir.path(), "alice", "alice@example.org");
	let config = config(dir.path());

	// Create prints the secret once.
	let mut out = Vec::new();
	assert_eq!(
		create(&config, "alice", "phone", None, None, None, &mut out),
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
	assert_eq!(list(&config, None, false, &mut out), ExitCode::SUCCESS);
	let listed = String::from_utf8(out).expect("utf8");
	assert!(listed.contains("alice"));
	assert!(listed.contains("phone"));
	assert!(!listed.contains("secret"));

	// Revoke removes it.
	let mut out = Vec::new();
	assert_eq!(
		revoke(&config, "alice", "phone", true, &mut out),
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
	seed_dynamic_account(dir.path(), "alice", "alice@example.org");
	let config = config(dir.path());
	let mut out = Vec::new();
	assert_eq!(
		create(
			&config,
			"alice",
			"phone",
			Some(9999),
			Some("203.0.113.0/24".to_string()),
			None,
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
	seed_dynamic_account(dir.path(), "alice", "alice@example.org");
	let config = config(dir.path());
	let mut out = Vec::new();
	assert_eq!(
		create(
			&config,
			"alice",
			"phone",
			None,
			Some("not-a-cidr".to_string()),
			None,
			&mut out,
		),
		ExitCode::from(2)
	);
}

#[test]
fn revoke_missing_label_fails() {
	let dir = tempfile::tempdir().expect("tempdir");
	seed_dynamic_account(dir.path(), "alice", "alice@example.org");
	let config = config(dir.path());
	let mut out = Vec::new();
	assert_eq!(
		revoke(&config, "alice", "absent", true, &mut out),
		ExitCode::from(2)
	);
}

#[test]
fn create_refuses_unknown_account_and_writes_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let mut out = Vec::new();
	let exit = create(&config, "ghost", "phone", None, None, None, &mut out);
	assert_eq!(exit, ExitCode::from(2), "unknown account must be refused");
	// The store has no row, so no orphan credential is left behind:
	// the check ran before any persistence.
	let store_path = dir.path().join("app_passwords.toml");
	assert!(
		!store_path.exists(),
		"store file must not appear on the refusal path"
	);
}

#[test]
fn create_refuses_static_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let toml = format!(
		"hostname = \"mail.example.org\"\n\
		 data_dir = \"{}\"\n\
		 \n\
		 [[accounts]]\n\
		 name = \"alice\"\n\
		 addresses = [\"alice@example.org\"]\n\
		 password_hash = \"stub\"\n",
		dir.path().display()
	);
	let config: Config = toml::from_str(&toml).expect("config");
	let mut out = Vec::new();
	let exit = create(&config, "alice", "phone", None, None, None, &mut out);
	assert_eq!(exit, ExitCode::from(2), "static account must be refused");
	assert!(!dir.path().join("app_passwords.toml").exists());
}
