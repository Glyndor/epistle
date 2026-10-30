//! The service locators follow the configuration: the set comes from the
//! listeners the operator configured, and the records carry one locator per
//! service in it, naming the port that service is reached at.

use super::*;
use crate::dns::provider::RecordKind;
use crate::dns::records::{DomainDkim, build_records};

/// The kinds of listener that advertise a mail protocol, with the service
/// each one exposes and the port its locator names when the listener keeps
/// the default.
const MAIL_KINDS: &[(&str, SrvService, u16)] = &[
	("imap", SrvService::Imap, 143),
	("imaps", SrvService::Imaps, 993),
	("submission", SrvService::Submission, 587),
	("submissions", SrvService::Submissions, 465),
	("pop3s", SrvService::Pop3, 995),
	("manage-sieve", SrvService::Sieve, 4190),
];

/// The API section. The JMAP locator names the API that serves it, and a
/// configuration without an API has no JMAP session to publish.
const API: &str = "[api]\ntoken_hash = 'sha256:0000000000000000000000000000000000000000000000000000000000000000'\n";

/// A configuration with the given listener blocks and one hosted domain.
fn config_with(listeners: &[&str]) -> crate::config::Config {
	build(listeners, "")
}

/// The same configuration with the API section in it.
fn config_with_api(listeners: &[&str]) -> crate::config::Config {
	build(listeners, API)
}

/// A configuration with the given listener blocks and one hosted domain,
/// with the API section in it when the caller asks for one.
fn build(listeners: &[&str], api: &str) -> crate::config::Config {
	let mut toml = String::from(
		"hostname = 'mail.example.org'\ndata_dir = '/var/lib/mail'\ndomains = ['example.org']\n",
	);
	toml.push_str(api);
	for listener in listeners {
		toml.push_str("\n[[listeners]]\n");
		toml.push_str(listener);
	}
	toml::from_str(&toml).expect("config")
}

/// The SRV records `build_records` publishes for the configured deployment.
fn published_srv(config: &crate::config::Config) -> Vec<(String, String)> {
	build_records(
		&["example.org".to_string()],
		"mail.example.org",
		&[],
		&DomainDkim::new(),
		None,
		"v1",
		ServiceRecords::from_config(config),
		None,
		None,
		None,
	)
	.into_iter()
	.filter(|entry| entry.record.kind == RecordKind::Srv)
	.map(|entry| (entry.record.name, entry.record.value))
	.collect()
}

#[test]
fn a_configuration_without_listeners_advertises_nothing() {
	let config = config_with(&[]);
	let services = ServiceRecords::from_config(&config);
	for service in SrvService::ALL {
		assert!(
			!services.contains(service),
			"{service:?} has no listener, so its locator is off"
		);
	}
	assert!(
		published_srv(&config).is_empty(),
		"a deployment with no listener publishes no SRV record"
	);
}

#[test]
fn one_listener_per_kind_publishes_its_own_locator() {
	for (kind, service, port) in MAIL_KINDS {
		let config = config_with(&[&format!("kind = '{kind}'")]);
		let records = published_srv(&config);
		assert_eq!(
			records,
			vec![(
				format!("{}._tcp.example.org", service.label()),
				format!("0 1 {port} mail.example.org."),
			)],
			"the {kind} listener alone publishes its own locator and nothing else"
		);
	}
}

#[test]
fn the_webdav_listener_brings_both_dav_services() {
	let config = config_with(&["kind = 'web-dav'"]);
	assert_eq!(
		published_srv(&config),
		vec![
			(
				"_caldavs._tcp.example.org".to_string(),
				"0 1 443 mail.example.org.".to_string(),
			),
			(
				"_carddavs._tcp.example.org".to_string(),
				"0 1 443 mail.example.org.".to_string(),
			),
		],
		"both DAV services share the listener and are reached over HTTPS"
	);
}

#[test]
fn the_api_listener_brings_jmap() {
	let config = config_with_api(&["kind = 'api'"]);
	assert_eq!(
		published_srv(&config),
		vec![(
			"_jmap._tcp.example.org".to_string(),
			"0 1 443 mail.example.org.".to_string(),
		)],
		"JMAP is reached over the public HTTPS endpoint, not over the API bind port"
	);
}

#[test]
fn the_api_listener_without_an_api_publishes_no_jmap() {
	// The listener names the port the API router binds, but a
	// configuration that carries no API has no JMAP session to point a
	// client at, so no locator is published.
	let config = config_with(&["kind = 'api'"]);
	assert!(
		published_srv(&config).is_empty(),
		"a deployment with no API publishes no JMAP locator"
	);
}

#[test]
fn an_api_without_the_listener_publishes_no_jmap() {
	// The API is configured but nothing serves it, so a client that
	// followed the locator would reach nothing.
	let config = config_with_api(&[]);
	assert!(
		published_srv(&config).is_empty(),
		"an API nobody listens on publishes no JMAP locator"
	);
}

#[test]
fn the_autoconfig_listener_brings_the_client_setup_names() {
	for kind in ["autoconfig", "autoconfigs"] {
		let config = config_with(&[&format!("kind = '{kind}'")]);
		assert!(
			ServiceRecords::from_config(&config).advertises_autodiscovery(),
			"the {kind} listener serves the client setup documents"
		);
	}
}

#[test]
fn a_deployment_without_the_autoconfig_listener_advertises_no_client_setup_names() {
	let config = config_with(&["kind = 'imap'"]);
	assert!(
		!ServiceRecords::from_config(&config).advertises_autodiscovery(),
		"a deployment that serves no client setup document advertises no name"
	);
}

#[test]
fn a_listener_on_two_addresses_is_one_locator() {
	let config = config_with(&[
		"kind = 'imap'\naddr = '0.0.0.0'",
		"kind = 'imap'\naddr = '::'",
	]);
	assert_eq!(
		published_srv(&config),
		vec![(
			"_imap._tcp.example.org".to_string(),
			"0 1 143 mail.example.org.".to_string(),
		)],
		"the same service on IPv4 and on IPv6 is one locator"
	);
}

#[test]
fn the_locator_names_the_port_the_listener_binds() {
	let config = config_with(&["kind = 'imaps'\nport = 2465"]);
	assert_eq!(
		published_srv(&config),
		vec![(
			"_imaps._tcp.example.org".to_string(),
			"0 1 2465 mail.example.org.".to_string(),
		)],
		"a client that follows the locator reaches the port the listener binds"
	);
}

#[test]
fn two_ports_of_the_same_service_are_two_locators() {
	let config = config_with(&["kind = 'imap'\nport = 1143", "kind = 'imap'\nport = 2143"]);
	assert_eq!(
		published_srv(&config),
		vec![
			(
				"_imap._tcp.example.org".to_string(),
				"0 1 1143 mail.example.org.".to_string(),
			),
			(
				"_imap._tcp.example.org".to_string(),
				"0 1 2143 mail.example.org.".to_string(),
			),
		],
		"two listeners of the same service on different ports are two locators"
	);
}

#[test]
fn the_records_carry_one_locator_per_enabled_service() {
	let config = config_with(&["kind = 'imap'", "kind = 'imaps'", "kind = 'submission'"]);
	let names: Vec<String> = published_srv(&config)
		.into_iter()
		.map(|(name, _)| name)
		.collect();
	assert_eq!(
		names,
		vec![
			"_submission._tcp.example.org".to_string(),
			"_imaps._tcp.example.org".to_string(),
			"_imap._tcp.example.org".to_string(),
		],
		"only the services the configuration enables get a locator"
	);
}

#[test]
fn the_records_of_a_full_deployment_carry_every_locator() {
	let config = config_with_api(&[
		"kind = 'imap'",
		"kind = 'imaps'",
		"kind = 'submission'",
		"kind = 'submissions'",
		"kind = 'pop3s'",
		"kind = 'manage-sieve'",
		"kind = 'api'",
		"kind = 'web-dav'",
	]);
	let names: Vec<String> = published_srv(&config)
		.into_iter()
		.map(|(name, _)| name)
		.collect();
	assert_eq!(names.len(), SrvService::ALL.len());
	for service in SrvService::ALL {
		let name = format!("{}._tcp.example.org", service.label());
		assert!(
			names.contains(&name),
			"{name} must be published when the service is on, got {names:?}"
		);
	}
}
