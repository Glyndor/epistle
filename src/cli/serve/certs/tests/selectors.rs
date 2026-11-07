//! The selectors the certificates role accepts in a hand-off request: the
//! ones the operator configured, which a rotation publishes and retires.

use super::*;

/// A configuration with a `[dkim]` block and one `[[dkim.domain]]` entry.
fn dkim_config(dir: &std::path::Path) -> Config {
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = '{}'\n\
		 [dkim]\nselector = 'mail'\nkey_file = '{}'\nrsa_selector = 'mailrsa'\nrsa_key_file = '{}'\n\
		 [[dkim.domain]]\nname = 'example.org'\nselector = 'custom'\nkey_file = '{}'\n",
		dir.join("data").display(),
		dir.join("mail.key").display(),
		dir.join("mailrsa.key").display(),
		dir.join("custom.key").display()
	))
	.expect("config")
}

#[test]
fn the_configured_selectors_are_the_ones_the_rotation_publishes_and_retires() {
	let dir = tempfile::tempdir().expect("directory");
	let selectors = configured_selectors(&dkim_config(dir.path()));
	assert_eq!(
		selectors,
		vec![
			"mail".to_string(),
			"mailrsa".to_string(),
			"custom".to_string()
		]
	);
}

#[test]
fn a_configuration_without_dkim_names_no_selector() {
	let dir = tempfile::tempdir().expect("directory");
	let selectors = configured_selectors(&config(dir.path(), Some("dns-01"), true));
	assert!(selectors.is_empty(), "{selectors:?}");
}
