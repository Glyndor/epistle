//! `dns-records` per-domain: a domain with `[dkim.domain]` publishes
//! its override's selector only, every other hosted domain keeps the
//! default.

use super::*;

fn per_domain_config(dir: &std::path::Path, default_sel: &str, override_sel: &str) -> Config {
	let toml = format!(
		r#"
hostname = "mail.example.org"
data_dir = {:?}

domains = ["example.org", "example.net"]

[dkim]
selector = "{}"
key_file = {:?}

[[dkim.domain]]
name = "example.org"
selector = "{}"
key_file = {:?}
"#,
		dir,
		default_sel,
		dir.join("default.key"),
		override_sel,
		dir.join("override.key"),
	);
	toml::from_str(&toml).expect("config")
}

#[test]
fn per_domain_override_publishes_only_the_override_selector() {
	let dir = tempfile::tempdir().expect("dir");
	let (default_pem, _) = crate::dkim::generate_key().expect("default key");
	let (override_pem, _) = crate::dkim::generate_key().expect("override key");
	std::fs::write(dir.path().join("default.key"), default_pem).expect("write default");
	std::fs::write(dir.path().join("override.key"), override_pem).expect("write override");
	let config = per_domain_config(dir.path(), "default-sel", "override-sel");
	let mut out = Vec::new();
	assert_eq!(run(&config, &mut out), ExitCode::SUCCESS);
	let text = String::from_utf8_lossy(&out);
	assert!(
		text.contains("override-sel._domainkey.example.org"),
		"the listed domain must publish its override selector: {text}"
	);
	assert!(
		!text.contains("default-sel._domainkey.example.org"),
		"the listed domain must NOT publish the default selector: {text}"
	);
	assert!(
		text.contains("default-sel._domainkey.example.net"),
		"the unlisted domain keeps the default selector: {text}"
	);
	assert!(
		!text.contains("override-sel._domainkey.example.net"),
		"the unlisted domain must NOT publish the override selector: {text}"
	);
}
