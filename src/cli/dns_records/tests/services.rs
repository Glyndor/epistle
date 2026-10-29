//! `dns-records` follows the configuration: a service the operator turned
//! off gets no locator, and every service they turned on gets one.
//!
//! A locator names a port the deployment answers on. A client that follows
//! the locator of a service nobody listens on reaches nothing, so the set
//! the command prints is the set the configuration enables.

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

/// The SRV records the command printed, by owner name.
fn srv_locators(text: &str) -> Vec<&str> {
	text.lines()
		.filter(|line| line.split_whitespace().nth(3) == Some("SRV"))
		.filter_map(|line| line.split_whitespace().next())
		.collect()
}

/// The SRV records the command prints for a configuration with these
/// listeners.
fn printed_locators(listeners: &[&str]) -> Vec<String> {
	let config = config_with(listeners);
	let mut out = Vec::new();
	assert_eq!(run(&config, false, &mut out), ExitCode::SUCCESS);
	let text = String::from_utf8(out).expect("utf-8");
	srv_locators(&text)
		.into_iter()
		.map(str::to_string)
		.collect()
}

#[test]
fn a_disabled_service_gets_no_locator() {
	// Only IMAP, IMAPS and submission are on. POP3, JMAP, ManageSieve and
	// the two WebDAV services are off, so no locator may name them: a
	// client that follows one of those reaches a port nothing listens on.
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
	for present in [
		"_imap._tcp.example.org",
		"_imaps._tcp.example.org",
		"_submission._tcp.example.org",
	] {
		assert!(
			printed.iter().any(|name| name == present),
			"{present} must be printed when the service is on, got {printed:?}"
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
		"_imap._tcp.example.org",
		"_imaps._tcp.example.org",
		"_submission._tcp.example.org",
		"_submissions._tcp.example.org",
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

#[test]
fn a_configuration_without_listeners_prints_no_locator() {
	// Nothing answers on any of the mail ports, so no locator may name
	// one of them.
	let printed = printed_locators(&[]);
	assert!(
		printed.is_empty(),
		"a deployment without listeners must print no SRV record, got {printed:?}"
	);
}
