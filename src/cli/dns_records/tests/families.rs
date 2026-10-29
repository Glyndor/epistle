//! The three families the design keeps apart from the mail protocols follow
//! the services that are on: the API, WebDAV and the client setup names.
//!
//! An operator reads the same set of records through three outputs: the
//! text of `dns-records`, its JSON, and the records `domain` prints for one
//! domain. They come from one set of records, so a family that is off is
//! missing from all three, and a family that is on is in all three.

use super::*;

/// The API section. The JMAP locator names the API that serves it, and a
/// configuration without an API has no JMAP session to publish.
const API: &str = "[api]\ntoken_hash = 'sha256:0000000000000000000000000000000000000000000000000000000000000000'\n";

/// The names of the three families.
const API_NAME: &str = "_jmap._tcp.example.org";
const DAV_NAMES: &[&str] = &["_caldavs._tcp.example.org", "_carddavs._tcp.example.org"];
const DISCOVERY_NAMES: &[&str] = &["autoconfig.example.org", "autodiscover.example.org"];

/// Every name of the three families.
fn names() -> impl Iterator<Item = &'static str> {
	[API_NAME]
		.into_iter()
		.chain(DAV_NAMES.iter().copied())
		.chain(DISCOVERY_NAMES.iter().copied())
}

/// A configuration with the given listeners and one hosted domain, with the
/// API section in it when the caller asks for one.
fn config_with(listeners: &[&str], api: bool) -> Config {
	let mut toml = String::from(
		"hostname = 'mail.example.org'\ndata_dir = '/var/lib/mail'\ndomains = ['example.org']\n",
	);
	if api {
		toml.push_str(API);
	}
	for kind in listeners {
		toml.push_str(&format!("\n[[listeners]]\nkind = '{kind}'\n"));
	}
	toml::from_str(&toml).expect("config")
}

/// The three outputs an operator reads, by name.
fn outputs(config: &Config) -> Vec<(&'static str, String)> {
	let mut text = Vec::new();
	assert_eq!(run(config, false, &mut text), ExitCode::SUCCESS);
	let mut json = Vec::new();
	assert_eq!(run(config, true, &mut json), ExitCode::SUCCESS);
	let mut domain = Vec::new();
	crate::cli::domain::domain_writers::print_domain_records(config, "example.org", &mut domain)
		.expect("print the records of the domain");
	vec![
		("text", String::from_utf8(text).expect("utf-8")),
		("json", String::from_utf8(json).expect("utf-8")),
		("domain", String::from_utf8(domain).expect("utf-8")),
	]
}

/// The outputs that name `name`.
fn outputs_naming(config: &Config, name: &str) -> Vec<&'static str> {
	outputs(config)
		.into_iter()
		.filter(|(_, text)| text.contains(name))
		.map(|(label, _)| label)
		.collect()
}

/// The outputs that do not name `name`.
fn outputs_not_naming(config: &Config, name: &str) -> Vec<&'static str> {
	outputs(config)
		.into_iter()
		.filter(|(_, text)| !text.contains(name))
		.map(|(label, _)| label)
		.collect()
}

#[test]
fn a_deployment_that_serves_none_of_them_publishes_none_of_them() {
	let config = config_with(&[], false);
	for name in names() {
		let named = outputs_naming(&config, name);
		assert!(
			named.is_empty(),
			"the {} output names {name}, which nothing serves",
			named.join(" and ")
		);
	}
}

#[test]
fn a_deployment_that_serves_them_publishes_all_of_them() {
	let config = config_with(&["api", "web-dav", "autoconfig"], true);
	for name in names() {
		let missing = outputs_not_naming(&config, name);
		assert!(
			missing.is_empty(),
			"the {} output does not name {name}",
			missing.join(" and ")
		);
	}
}

#[test]
fn the_api_family_needs_the_api_that_serves_it() {
	// The listener names the port the API router binds, but without the
	// section there is no API and no JMAP session to point a client at.
	let config = config_with(&["api", "web-dav", "autoconfig"], false);
	let named = outputs_naming(&config, API_NAME);
	assert!(
		named.is_empty(),
		"the {} output names {API_NAME}, which no API serves",
		named.join(" and ")
	);
	for name in DAV_NAMES.iter().chain(DISCOVERY_NAMES) {
		let missing = outputs_not_naming(&config, name);
		assert!(
			missing.is_empty(),
			"the {} output does not name {name}",
			missing.join(" and ")
		);
	}
}

#[test]
fn the_webdav_family_is_one_listener_for_both_services() {
	// CalDAV and CardDAV share the listener and no flag turns one of them
	// off, so both names appear or neither does.
	let config = config_with(&["web-dav"], false);
	for name in DAV_NAMES {
		let missing = outputs_not_naming(&config, name);
		assert!(
			missing.is_empty(),
			"the {} output does not name {name}",
			missing.join(" and ")
		);
	}
}
