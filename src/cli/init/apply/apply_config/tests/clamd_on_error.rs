//! `init` writes `clamd_on_error = "defer"` into a new configuration with
//! clamd, and never into an existing one.

use super::*;

fn desired_toml(antivirus: Option<bool>) -> String {
	let mut answers = crate::cli::init::compose::minimal_answers();
	answers.services.antivirus = antivirus;
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

fn on_error(config: &toml::Value) -> Option<&str> {
	config
		.get("antispam")
		.and_then(|antispam| antispam.get("clamd_on_error"))
		.and_then(toml::Value::as_str)
}

#[test]
fn a_new_configuration_defers_mail_clamd_cannot_scan() {
	let config: toml::Value = toml::from_str(&desired_toml(None)).unwrap();
	assert_eq!(on_error(&config), Some("defer"));
	let config: toml::Value = toml::from_str(&desired_toml(Some(false))).unwrap();
	assert_eq!(on_error(&config), None, "no clamd, nothing to defer for");
}

#[test]
fn an_existing_configuration_keeps_its_clamd_on_error() {
	let dir = tempfile::tempdir_in(".").expect("tempdir");
	for (existing, expected) in [
		(
			"hostname = \"old.example.org\"\n[antispam]\nclamd_socket = \"/run/clamav/clamd.sock\"\n",
			None,
		),
		(
			"hostname = \"old.example.org\"\n[antispam]\nclamd_socket = \"/run/clamav/clamd.sock\"\nclamd_on_error = \"accept\"\n",
			Some("accept"),
		),
	] {
		let path = dir.path().join("mail.toml");
		std::fs::write(&path, existing).expect("write config");
		let _ = merge_with_existing(&path, &desired_toml(None), false);
		let merged: toml::Value =
			toml::from_str(&std::fs::read_to_string(&path).expect("read back")).expect("toml");
		assert_eq!(on_error(&merged), expected, "merged into {existing:?}");
		assert_eq!(
			merged.get("hostname").and_then(toml::Value::as_str),
			Some("mail.example.org"),
			"the merge itself ran"
		);
	}
}
