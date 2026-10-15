//! `init` writes the attachment policy into a new configuration only.

use super::*;

fn desired_toml() -> String {
	let answers = crate::cli::init::compose::minimal_answers();
	let desired = build_config(
		&answers,
		"::".parse().unwrap(),
		Some(Path::new("/key")),
		None,
		Path::new("/cert"),
		Path::new("/tls-key"),
	)
	.unwrap();
	toml::to_string(&desired).unwrap()
}

#[test]
fn a_new_configuration_quarantines_disguised_attachments() {
	let config: toml::Value = toml::from_str(&desired_toml()).unwrap();
	let section = config.get("attachments").expect("[attachments] written");
	assert_eq!(
		section.get("mode").and_then(toml::Value::as_str),
		Some("quarantine")
	);
	assert_eq!(
		section.get("macros").and_then(toml::Value::as_str),
		Some("quarantine")
	);
	assert_eq!(
		section
			.get("encrypted_archives")
			.and_then(toml::Value::as_str),
		Some("flag")
	);
}

#[test]
fn an_existing_configuration_keeps_its_attachment_policy() {
	let dir = tempfile::tempdir_in(".").expect("tempdir");
	for (existing, expected) in [
		("hostname = \"old.example.org\"\n", None),
		(
			"hostname = \"old.example.org\"\n[attachments]\nmode = \"flag\"\n",
			Some("flag"),
		),
	] {
		let path = dir.path().join("mail.toml");
		std::fs::write(&path, existing).expect("write config");
		let _ = merge_with_existing(&path, &desired_toml(), false);
		let merged: toml::Value =
			toml::from_str(&std::fs::read_to_string(&path).expect("read back")).expect("toml");
		assert_eq!(
			merged
				.get("attachments")
				.and_then(|section| section.get("mode"))
				.and_then(toml::Value::as_str),
			expected,
			"merged into {existing:?}"
		);
		assert_eq!(
			merged.get("hostname").and_then(toml::Value::as_str),
			Some("mail.example.org"),
			"the merge itself ran"
		);
	}
}
