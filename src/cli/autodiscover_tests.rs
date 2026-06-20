//! Tests for the Microsoft Autodiscover emitter.

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
fn emits_autodiscover_for_default_domain() {
	let config = config(&["example.org", "example.net"]);
	let mut out = Vec::new();
	assert_eq!(run(&config, None, &mut out), ExitCode::SUCCESS);
	let xml = String::from_utf8(out).expect("utf8");
	assert!(
		xml.contains("schemas.microsoft.com/exchange/autodiscover"),
		"{xml}"
	);
	assert!(xml.contains("<Type>IMAP</Type>"), "{xml}");
	assert!(xml.contains("<Type>SMTP</Type>"), "{xml}");
	assert!(xml.contains("<Server>mail.example.org</Server>"), "{xml}");
	assert!(xml.contains("<Port>993</Port>"), "{xml}");
	assert!(xml.contains("<Port>587</Port>"), "{xml}");
	assert!(xml.contains("<AuthRequired>on</AuthRequired>"), "{xml}");
}

#[test]
fn accepts_named_domain() {
	let config = config(&["example.org", "example.net"]);
	let mut out = Vec::new();
	assert_eq!(
		run(&config, Some("example.net"), &mut out),
		ExitCode::SUCCESS
	);
	assert!(!out.is_empty());
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

#[test]
fn no_domains_fails() {
	let toml = "hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n";
	let config: Config = toml::from_str(toml).expect("config parses");
	let mut out = Vec::new();
	assert_eq!(run(&config, None, &mut out), ExitCode::FAILURE);
	assert!(out.is_empty());
}

#[test]
fn hostname_is_xml_escaped() {
	// A hostname can never contain `<`, but the emitter must still escape
	// defensively so a future caller cannot inject markup.
	let xml = crate::autodiscovery::autodiscover("a<b&c");
	assert!(xml.contains("a&lt;b&amp;c"), "{xml}");
}
