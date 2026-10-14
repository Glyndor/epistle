//! Per-domain DKIM in `status`: a domain with `[dkim.domain]` is
//! checked against its own key, not the default.

use super::*;
use std::path::PathBuf;

fn per_domain_fixture() -> (tempfile::TempDir, Config) {
	let dir = tempfile::tempdir().expect("dir");
	let (default_pem, _) = crate::dkim::generate_key().expect("default key");
	let (override_pem, _) = crate::dkim::generate_key().expect("override key");
	let default_key: PathBuf = dir.path().join("default.key");
	let override_key: PathBuf = dir.path().join("override.key");
	std::fs::write(&default_key, default_pem).expect("write default");
	std::fs::write(&override_key, override_pem).expect("write override");
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
	(dir, config)
}

#[test]
fn signing_keys_lists_default_and_per_domain_entries() {
	let (_dir, config) = per_domain_fixture();
	let keys = signing_keys(&config).expect("keys");
	// Two default keys (ed25519, RSA not configured) plus one per-domain
	// override (ed25519, no RSA).
	assert_eq!(keys.len(), 2);
	let default = keys
		.iter()
		.find(|k| k.domain.is_none())
		.expect("the default key");
	assert_eq!(default.key.selector, "default-sel");
	let per = keys
		.iter()
		.find(|k| k.domain.as_deref() == Some("example.org"))
		.expect("the per-domain key");
	assert_eq!(per.key.selector, "per-sel");
}

#[test]
fn a_per_domain_override_lists_its_own_domain_only() {
	let (_dir, config) = per_domain_fixture();
	let keys = signing_keys(&config).expect("keys");
	let per = keys
		.iter()
		.find(|k| k.domain.is_some())
		.expect("per-domain key");
	// The override is bound to example.org and is not the default;
	// the loop in dns_area uses `key.domain` to decide which domain
	// the key applies to.
	assert_eq!(per.domain.as_deref(), Some("example.org"));
}
