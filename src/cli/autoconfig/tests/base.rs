//! Tests for the Thunderbird autoconfig emitter.

use super::*;

fn config(domains: &[&str]) -> Config {
	let list = domains
		.iter()
		.map(|d| format!("\"{d}\""))
		.collect::<Vec<_>>()
		.join(", ");
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\ndomains = [{list}]\n"
	);
	toml::from_str(&toml).expect("config parses")
}

#[test]
fn emits_autoconfig_for_default_domain() {
	let config = config(&["example.org", "example.net"]);
	let mut out = Vec::new();
	assert_eq!(run(&config, None, &mut out), ExitCode::SUCCESS);
	let xml = String::from_utf8(out).expect("utf8");
	assert!(xml.contains("<clientConfig version=\"1.1\">"), "{xml}");
	// Defaults to the first configured domain.
	assert!(xml.contains("<emailProvider id=\"example.org\">"), "{xml}");
	assert!(
		xml.contains("<hostname>mail.example.org</hostname>"),
		"{xml}"
	);
	assert!(xml.contains("<port>993</port>"), "{xml}");
	assert!(xml.contains("<port>587</port>"), "{xml}");
	assert!(xml.contains("%EMAILADDRESS%"), "{xml}");
}

#[test]
fn emits_for_named_domain() {
	let config = config(&["example.org", "example.net"]);
	let mut out = Vec::new();
	assert_eq!(
		run(&config, Some("example.net"), &mut out),
		ExitCode::SUCCESS
	);
	let xml = String::from_utf8(out).expect("utf8");
	assert!(xml.contains("<emailProvider id=\"example.net\">"), "{xml}");
}

#[test]
fn unconfigured_domain_fails() {
	let config = config(&["example.org"]);
	let mut out = Vec::new();
	assert_eq!(
		run(&config, Some("other.example"), &mut out),
		ExitCode::FAILURE
	);
	assert!(out.is_empty());
}
