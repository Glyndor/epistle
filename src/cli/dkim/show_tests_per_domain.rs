//! Per-domain DKIM in `dkim show`: the view lists each override's
//! selector and key file, and DNS comparisons use the override's
//! selector for the domain that names it.

use super::*;
use crate::dkim::test_support::KeyDns;
use std::collections::HashMap;
use std::path::PathBuf;

fn per_domain_fixture() -> (tempfile::TempDir, Config, String, String) {
	let dir = tempfile::tempdir().expect("dir");
	let (default_pem, _) = crate::dkim::generate_key().expect("default key");
	let (override_pem, _) = crate::dkim::generate_key().expect("override key");
	let default_key: PathBuf = dir.path().join("default.key");
	let override_key: PathBuf = dir.path().join("override.key");
	std::fs::write(&default_key, default_pem).expect("write default");
	std::fs::write(&override_key, override_pem).expect("write override");
	let default_value = Signer::load("default-sel", &default_key)
		.expect("default signer")
		.dns_record_value();
	let override_value = Signer::load("per-sel", &override_key)
		.expect("override signer")
		.dns_record_value();
	let toml = format!(
		r#"
hostname = "mail.example.org"
data_dir = {:?}
domains = ["example.org", "example.net"]

[dkim]
selector = "default-sel"
key_file = {:?}

[[dkim.domain]]
name = "example.org"
selector = "per-sel"
key_file = {:?}
"#,
		dir.path(),
		default_key,
		override_key,
	);
	let config: Config = toml::from_str(&toml).expect("config");
	(dir, config, default_value, override_value)
}

#[tokio::test]
async fn per_domain_override_is_listed_in_the_view() {
	let (_dir, config, _default_value, _override_value) = per_domain_fixture();
	let view = build(&config, None).await.expect("view");
	assert_eq!(view.overrides.len(), 1, "one per-domain override");
	let entry = &view.overrides[0];
	assert_eq!(entry.domain, "example.org");
	assert_eq!(entry.selector, "per-sel");
	assert!(
		entry.key_file.ends_with("override.key"),
		"the override entry points at the operator-configured file"
	);
}

#[tokio::test]
async fn per_domain_record_uses_the_override_selector() {
	let (_dir, config, _default_value, override_value) = per_domain_fixture();
	let mut records = HashMap::new();
	records.insert(
		"per-sel._domainkey.example.org".to_string(),
		vec![override_value],
	);
	records.insert(
		"default-sel._domainkey.example.net".to_string(),
		vec!["v=DKIM1; k=ed25519; p=ZZZZ".to_string()],
	);
	let dns = KeyDns(records);
	let view = build(&config, Some(&dns)).await.expect("view");
	let org = view
		.records
		.iter()
		.find(|r| r.domain == "example.org")
		.expect("example.org record");
	assert_eq!(
		org.selector, "per-sel",
		"example.org must use the override selector"
	);
	assert_eq!(org.source, "dkim.domain");
	let net = view
		.records
		.iter()
		.find(|r| r.domain == "example.net")
		.expect("example.net record");
	assert_eq!(
		net.selector, "default-sel",
		"example.net keeps the default selector"
	);
	assert_eq!(net.source, "dkim");
	assert_eq!(
		view.records.len(),
		2,
		"one record per domain (overrides collapse the default list)"
	);
}
