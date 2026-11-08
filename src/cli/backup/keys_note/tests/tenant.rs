//! The backup warning names every tenant and retired key file.

use super::*;

#[test]
fn tenant_and_retired_key_files_are_listed_by_path_only() {
	let dir = tempfile::tempdir().expect("tempdir");
	let acme = dir.path().join("acme.key");
	let old = dir.path().join("old.key");
	let key = crate::storage::generate_key_base64().expect("csprng");
	std::fs::write(&acme, &key).expect("key");
	let mut config: crate::config::Config = toml::from_str(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["acme.example", "other.example"]

[[tenant]]
name = "acme"
domains = ["acme.example"]

[[tenant]]
name = "other"
domains = ["other.example"]
"#,
	)
	.expect("config");
	config.tenants[0].encryption_key_file = Some(acme.clone());
	config.storage = Some(crate::config::Storage {
		retired_key_files: vec![old.clone()],
		..crate::config::Storage::default()
	});
	let lines = tenant_and_retired_keys(&config);
	assert_eq!(lines.len(), 2, "{lines:?}");
	assert!(lines[0].contains("\"acme\"") && lines[0].contains(acme.to_str().expect("utf8")));
	assert!(lines[1].contains(old.to_str().expect("utf8")));
	assert!(
		lines.iter().all(|line| !line.contains(&key)),
		"no key material"
	);
}
