//! The records `domain add` prints follow the configuration too: a service
//! the operator turned off gets no locator.

use super::*;

/// A configuration with the given listeners and one hosted domain. The API
/// section is there because the JMAP locator names the API that serves it,
/// and a configuration without an API has no JMAP session to publish.
fn config_with(listeners: &[&str]) -> Config {
	let mut toml = String::from(
		"hostname = 'mail.example.org'\ndata_dir = '/var/lib/mail'\ndomains = ['example.org']\n\
		 [api]\n\
		 token_hash = 'sha256:0000000000000000000000000000000000000000000000000000000000000000'\n",
	);
	for kind in listeners {
		toml.push_str(&format!("\n[[listeners]]\nkind = '{kind}'\n"));
	}
	toml::from_str(&toml).expect("config")
}

/// The SRV records the command printed for the domain.
fn printed_locators(listeners: &[&str]) -> Vec<String> {
	let config = config_with(listeners);
	let mut out = Vec::new();
	print_domain_records(&config, "example.org", &mut out).expect("print");
	let text = String::from_utf8(out).expect("utf-8");
	text.lines()
		.filter(|line| line.split_whitespace().nth(3) == Some("SRV"))
		.filter_map(|line| line.split_whitespace().next())
		.map(str::to_string)
		.collect()
}

#[test]
fn a_disabled_service_gets_no_locator() {
	let printed = printed_locators(&["imap", "imaps", "submission"]);
	for absent in [
		"_pop3s._tcp.example.org",
		"_jmap._tcp.example.org",
		"_sieve._tcp.example.org",
		"_caldavs._tcp.example.org",
		"_carddavs._tcp.example.org",
	] {
		assert!(
			!printed.iter().any(|name| name == absent),
			"{absent} must not be printed when the service is off, got {printed:?}"
		);
	}
}

#[test]
fn every_enabled_service_gets_its_locator() {
	let printed = printed_locators(&[
		"imap",
		"imaps",
		"submission",
		"submissions",
		"pop3s",
		"manage-sieve",
		"api",
		"web-dav",
	]);
	for present in [
		"_pop3s._tcp.example.org",
		"_jmap._tcp.example.org",
		"_sieve._tcp.example.org",
		"_caldavs._tcp.example.org",
		"_carddavs._tcp.example.org",
	] {
		assert!(
			printed.iter().any(|name| name == present),
			"{present} must be printed when the service is on, got {printed:?}"
		);
	}
}
