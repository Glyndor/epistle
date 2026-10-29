//! Tests for `epistle api-key rotate`.

use super::*;
use crate::api::api_keys::sha256_token_matches;

fn config(data_dir: &std::path::Path) -> Config {
	toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
		data_dir.display()
	))
	.expect("config parses")
}

fn create_key(config: &Config, label: &str) -> String {
	let mut out = Vec::new();
	assert_eq!(
		create(
			config,
			NewKey {
				label: label.to_string(),
				expires_at: Some(4_000_000_000),
				ip_cidr: Some("203.0.113.0/24".into()),
				scopes: vec!["read".into(), "send".into()],
				domains: vec!["example.org".into()],
				account: None,
				class: None,
			},
			false,
			&mut out,
			&mut Vec::new()
		),
		ExitCode::SUCCESS
	);
	secret_in(&out)
}

fn secret_in(out: &[u8]) -> String {
	String::from_utf8_lossy(out)
		.lines()
		.find_map(|line| line.strip_prefix("key (shown once): "))
		.expect("secret line")
		.to_string()
}

#[test]
fn rotate_keeps_every_attribute_and_swaps_the_secret() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path());
	let old = create_key(&config, "ci");
	let before = ApiKeyStore::open(dir.path()).expect("open").keys()[0].clone();

	let mut out = Vec::new();
	assert_eq!(rotate(&config, "ci", false, &mut out), ExitCode::SUCCESS);
	let new = secret_in(&out);

	let store = ApiKeyStore::open(dir.path()).expect("open");
	assert_eq!(store.keys().len(), 1, "rotation must not add a second key");
	let after = &store.keys()[0];
	assert_eq!(after.label, before.label);
	assert_eq!(after.scopes, before.scopes);
	assert_eq!(after.domains, before.domains);
	assert_eq!(after.expires_at, before.expires_at);
	assert_eq!(after.ip_cidr, before.ip_cidr);
	assert!(
		sha256_token_matches(&after.hash, &new),
		"new secret must match"
	);
	assert!(
		!sha256_token_matches(&after.hash, &old),
		"old secret must stop matching"
	);
	assert_ne!(old, new);
}

#[test]
fn rotate_unknown_label_fails_and_changes_nothing() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path());
	create_key(&config, "ci");
	let before = std::fs::read(dir.path().join("api_keys.toml")).expect("file");

	let mut out = Vec::new();
	assert_eq!(
		rotate(&config, "missing", false, &mut out),
		ExitCode::FAILURE
	);

	assert!(out.is_empty(), "a failed rotation prints no secret");
	assert_eq!(
		std::fs::read(dir.path().join("api_keys.toml")).expect("file"),
		before
	);
}

#[test]
fn rotate_output_never_shows_the_hash() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path());
	create_key(&config, "ci");
	let mut out = Vec::new();
	assert_eq!(rotate(&config, "ci", false, &mut out), ExitCode::SUCCESS);
	assert!(!String::from_utf8_lossy(&out).contains("sha256:"));
}

#[test]
fn a_class_bound_at_creation_follows_the_key_through_a_rotation() {
	use crate::evidence::bindings::{BindingSet, api_key_key_of_token};
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let mut out = Vec::new();
	let created = create(
		&config,
		NewKey {
			label: "notices".into(),
			scopes: vec!["send".into()],
			class: Some(crate::evidence::MailClass::Transactional),
			..NewKey::default()
		},
		false,
		&mut out,
		&mut Vec::new(),
	);
	assert_eq!(created, ExitCode::SUCCESS);
	let first = secret_in(&out);
	let class = |token: &str| {
		BindingSet::open(dir.path())
			.expect("bindings")
			.credential(&api_key_key_of_token(token))
	};
	assert_eq!(
		class(&first),
		Some(crate::evidence::MailClass::Transactional)
	);
	let mut rotated = Vec::new();
	assert_eq!(
		rotate(&config, "notices", false, &mut rotated),
		ExitCode::SUCCESS
	);
	let second = secret_in(&rotated);
	assert_eq!(
		class(&second),
		Some(crate::evidence::MailClass::Transactional)
	);
	assert_eq!(class(&first), None, "the retired secret keeps a binding");
}
