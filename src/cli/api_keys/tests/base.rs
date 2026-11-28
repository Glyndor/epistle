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
				auto_submitted: false,
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
				auto_submitted: false,
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
				auto_submitted: false,
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
				auto_submitted: false,
			},
			false,
			&mut out,
			&mut Vec::new()
		),
		ExitCode::from(2)
	);
}

/// The command takes as many domains as it is asked for: the cap of the API
/// is not the command's, and the command had no cap before 0.15.0 either.
#[test]
fn create_takes_more_domains_than_the_api_allows() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let domains: Vec<String> = (0..=crate::api::api_keys::issue::MAX_DOMAINS)
		.map(|n| format!("d{n}.example"))
		.collect();
	let mut out = Vec::new();
	assert_eq!(
		create(
			&config,
			NewKey {
				label: "wide".to_string(),
				expires_at: None,
				ip_cidr: None,
				scopes: read_scope(),
				domains,
				account: None,
				class: None,
				auto_submitted: false,
			},
			false,
			&mut out,
			&mut Vec::new()
		),
		ExitCode::SUCCESS
	);
	let store = ApiKeyStore::open(dir.path()).expect("open");
	assert_eq!(
		store.keys()[0].domains.len(),
		crate::api::api_keys::issue::MAX_DOMAINS + 1
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
	for label in [
		"",
		"  ",
		"ci\nprod",
		"\u{202e}ci",
		"ci\u{2028}prod",
		"ci\u{61c}",
		" ci",
		&"a".repeat(65),
	] {
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
				auto_submitted: false,
			},
			false,
			&mut Vec::new(),
			&mut Vec::new(),
		);
		assert_eq!(code, ExitCode::from(crate::cli::exit::REFUSED), "{label:?}");
	}
	assert!(
		ApiKeyStore::open(dir.path())
			.expect("open")
			.keys()
			.is_empty()
	);
}

fn new_key(label: &str, auto_submitted: bool) -> NewKey {
	NewKey {
		label: label.to_string(),
		expires_at: Some(4_000_000_000),
		ip_cidr: Some("10.0.0.0/8".to_string()),
		scopes: vec!["send".to_string(), "read".to_string()],
		domains: vec!["example.org".to_string()],
		account: None,
		class: None,
		auto_submitted,
	}
}

fn listing(config: &Config, json: bool) -> String {
	let mut out = Vec::new();
	assert_eq!(
		list(config, json, &mut out, &mut Vec::new()),
		ExitCode::SUCCESS
	);
	String::from_utf8(out).expect("utf8")
}

#[test]
fn create_with_auto_submitted_persists_and_lists_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	assert_eq!(
		create(
			&config,
			new_key("apps", true),
			false,
			&mut Vec::new(),
			&mut Vec::new()
		),
		ExitCode::SUCCESS
	);
	assert!(ApiKeyStore::open(dir.path()).expect("open").keys()[0].auto_submitted);
	let text = listing(&config, false);
	assert!(text.contains("auto_submitted=on"), "{text}");
	let json: serde_json::Value =
		serde_json::from_str(&listing(&config, true)).expect("valid JSON");
	assert_eq!(json[0]["auto_submitted"], serde_json::json!(true), "{json}");
}

#[test]
fn create_without_auto_submitted_defaults_to_off() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	assert_eq!(
		create(
			&config,
			new_key("people", false),
			false,
			&mut Vec::new(),
			&mut Vec::new()
		),
		ExitCode::SUCCESS
	);
	assert!(!ApiKeyStore::open(dir.path()).expect("open").keys()[0].auto_submitted);
	let text = listing(&config, false);
	assert!(text.contains("auto_submitted=off"), "{text}");
	assert!(!text.contains("auto_submitted=on"), "{text}");
	let json: serde_json::Value =
		serde_json::from_str(&listing(&config, true)).expect("valid JSON");
	assert!(
		json[0].get("auto_submitted").is_none(),
		"a disabled key keeps the existing JSON shape: {json}"
	);
}

#[test]
fn set_auto_submitted_updates_the_stored_key() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	assert_eq!(
		create(
			&config,
			new_key("apps", false),
			false,
			&mut Vec::new(),
			&mut Vec::new()
		),
		ExitCode::SUCCESS
	);
	let before = ApiKeyStore::open(dir.path()).expect("open").keys()[0].clone();
	for state in [true, false] {
		let mut out = Vec::new();
		assert_eq!(
			set_auto_submitted(&config, "apps", state, false, &mut out),
			ExitCode::SUCCESS
		);
		let store = ApiKeyStore::open(dir.path()).expect("open");
		let after = &store.keys()[0];
		assert_eq!(after.auto_submitted, state);
		assert_eq!(after.hash, before.hash);
		assert_eq!(after.scopes, before.scopes);
		assert_eq!(after.domains, before.domains);
		assert_eq!(after.expires_at, before.expires_at);
		assert_eq!(after.ip_cidr, before.ip_cidr);
		assert_eq!(after.account, before.account);
	}
}

#[test]
fn set_auto_submitted_on_a_missing_label_fails_and_writes_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	assert_eq!(
		set_auto_submitted(&config, "absent", true, false, &mut Vec::new()),
		ExitCode::from(2)
	);
	assert!(!dir.path().join("api_keys.toml").exists());
}
