//! The client setup locator (`_autoconfig._tcp`) follows the `autoconfigs`
//! listener, and only that one: the plain `autoconfig` listener sits behind
//! the operator's own TLS proxy, so a locator naming its port would send a
//! client to a port that does not speak the protocol it expects.

use super::*;
use crate::dns::provider::RecordKind;
use crate::dns::records::{DomainDkim, build_records};

fn config_with(listeners: &[&str]) -> crate::config::Config {
	let mut toml = String::from(
		"hostname = 'mail.example.org'\ndata_dir = '/var/lib/mail'\ndomains = ['example.org']\n",
	);
	for listener in listeners {
		toml.push_str("\n[[listeners]]\n");
		toml.push_str(listener);
	}
	toml::from_str(&toml).expect("config")
}

/// The `(kind, name, value)` of the records the client setup produces.
fn published(config: &crate::config::Config) -> Vec<(RecordKind, String, String)> {
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
	.filter(|entry| {
		matches!(entry.record.kind, RecordKind::Srv | RecordKind::Cname)
			&& (entry.record.name.starts_with("_autoconfig")
				|| entry.record.name.starts_with("autoconfig.")
				|| entry.record.name.starts_with("autodiscover."))
	})
	.map(|entry| (entry.record.kind, entry.record.name, entry.record.value))
	.collect()
}

#[test]
fn the_autoconfigs_listener_publishes_the_locator_and_the_names() {
	let config = config_with(&["kind = 'autoconfigs'"]);
	let services = ServiceRecords::from_config(&config);
	assert!(services.advertises_autodiscovery());
	assert!(services.contains(SrvService::Autoconfig));
	let records = published(&config);
	let names: Vec<&str> = records.iter().map(|(_, n, _)| n.as_str()).collect();
	for expected in [
		"autoconfig.example.org",
		"autodiscover.example.org",
		"_autoconfig._tcp.example.org",
	] {
		assert!(names.contains(&expected), "{expected} missing: {records:?}");
	}
}

#[test]
fn the_locator_value_is_priority_weight_port_and_a_rooted_hostname() {
	let records = published(&config_with(&["kind = 'autoconfigs'"]));
	let locator = records
		.iter()
		.find(|(kind, name, _)| *kind == RecordKind::Srv && name.starts_with("_autoconfig"))
		.expect("the locator");
	assert_eq!(locator.2, "0 1 443 mail.example.org.");
}

#[test]
fn the_plain_autoconfig_listener_publishes_the_names_but_no_locator() {
	let config = config_with(&["kind = 'autoconfig'"]);
	let services = ServiceRecords::from_config(&config);
	assert!(services.advertises_autodiscovery());
	assert!(!services.contains(SrvService::Autoconfig));
	assert!(SrvService::of_listener(ListenerKind::Autoconfig).is_empty());
	let records = published(&config);
	assert!(
		!records.iter().any(|(kind, _, _)| *kind == RecordKind::Srv),
		"{records:?}"
	);
	assert_eq!(records.len(), 2, "only the two CNAMEs: {records:?}");
}

#[test]
fn a_configuration_without_either_listener_publishes_none_of_it() {
	let config = config_with(&["kind = 'imaps'"]);
	let services = ServiceRecords::from_config(&config);
	assert!(!services.advertises_autodiscovery());
	assert!(!services.contains(SrvService::Autoconfig));
	assert!(published(&config).is_empty());
}
