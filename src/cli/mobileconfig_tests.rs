//! Tests for the Apple `.mobileconfig` profile generator.

use super::*;
use crate::config::Config;

fn config_with_alice(data_dir: &std::path::Path) -> Config {
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = {data_dir:?}\ndomains = [\"example.org\"]\n\n\
		 [[accounts]]\nname = \"alice\"\naddresses = [\"alice@example.org\"]\n",
	);
	toml::from_str(&toml).expect("config parses")
}

#[test]
fn emits_profile_for_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config_with_alice(dir.path());
	let mut out = Vec::new();
	assert_eq!(run(&config, "alice", &mut out), ExitCode::SUCCESS);
	let xml = String::from_utf8(out).expect("utf8");
	assert!(xml.contains("<plist version=\"1.0\">"), "{xml}");
	assert!(xml.contains("com.apple.mail.managed"), "{xml}");
	assert!(xml.contains("<string>alice@example.org</string>"), "{xml}");
	assert!(xml.contains("<string>mail.example.org</string>"), "{xml}");
	// IMAP 993 implicit TLS, submission 587.
	assert!(xml.contains("<integer>993</integer>"), "{xml}");
	assert!(xml.contains("<integer>587</integer>"), "{xml}");
}

#[test]
fn unknown_account_fails() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config_with_alice(dir.path());
	let mut out = Vec::new();
	assert_eq!(run(&config, "ghost", &mut out), ExitCode::FAILURE);
	assert!(out.is_empty());
}

#[test]
fn escapes_xml_special_characters() {
	assert_eq!(escape("a&b<c>\"d'"), "a&amp;b&lt;c&gt;&quot;d&apos;");
}
