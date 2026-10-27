//! The service locators follow the configuration: the set comes from the
//! listeners the operator configured, and the records carry one locator per
//! service in it.

use super::*;
use crate::dns::provider::RecordKind;
use crate::dns::records::{DomainDkim, build_records};

/// A configuration with the given listeners and one hosted domain.
fn config_with(listeners: &[&str]) -> crate::config::Config {
	let mut toml = String::from(
		"hostname = 'mail.example.org'\ndata_dir = '/var/lib/mail'\ndomains = ['example.org']\n",
	);
	for kind in listeners {
		toml.push_str(&format!("\n[[listeners]]\nkind = '{kind}'\n"));
	}
	toml::from_str(&toml).expect("config")
}

/// The SRV records the builder publishes for one domain.
fn srv_names(services: Services) -> Vec<String> {
	let records = build_records(
		&["example.org".to_string()],
		"mail.example.org",
		&[],
		&DomainDkim::new(),
		None,
		"v1",
		services,
		None,
		None,
		None,
	);
	records
		.iter()
		.filter(|entry| entry.record.kind == RecordKind::Srv)
		.map(|entry| entry.record.name.clone())
		.collect()
}

#[test]
fn every_listener_turns_its_locator_on() {
	let config = config_with(&[
		"imap",
		"imaps",
		"submission",
		"submissions",
		"pop3s",
		"manage-sieve",
		"api",
		"web-dav",
	]);
	let services = Services::from_config(&config);
	for service in SrvService::ALL {
		assert!(
			services.contains(service),
			"the listener behind {:?} is configured, so its locator is on",
			service
		);
	}
}

#[test]
fn a_service_without_a_listener_has_no_locator() {
	let config = config_with(&["imap", "imaps", "submission"]);
	let services = Services::from_config(&config);
	assert!(services.contains(SrvService::Imap));
	assert!(services.contains(SrvService::Imaps));
	assert!(services.contains(SrvService::Submission));
	for off in [
		SrvService::Submissions,
		SrvService::Pop3,
		SrvService::Jmap,
		SrvService::Sieve,
		SrvService::Caldav,
		SrvService::Carddav,
	] {
		assert!(
			!services.contains(off),
			"{off:?} has no listener, so its locator is off"
		);
	}
}

#[test]
fn the_webdav_listener_brings_both_dav_services() {
	let config = config_with(&["web-dav"]);
	let services = Services::from_config(&config);
	assert!(services.contains(SrvService::Caldav));
	assert!(services.contains(SrvService::Carddav));
}

#[test]
fn the_api_listener_brings_jmap() {
	let config = config_with(&["api"]);
	let services = Services::from_config(&config);
	assert!(services.contains(SrvService::Jmap));
}

#[test]
fn a_configuration_without_listeners_advertises_nothing() {
	let config = config_with(&[]);
	let services = Services::from_config(&config);
	for service in SrvService::ALL {
		assert!(
			!services.contains(service),
			"{service:?} has no listener, so its locator is off"
		);
	}
}

#[test]
fn the_records_carry_one_locator_per_enabled_service() {
	let config = config_with(&["imap", "imaps", "submission"]);
	let names = srv_names(Services::from_config(&config));
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
	let config = config_with(&[
		"imap",
		"imaps",
		"submission",
		"submissions",
		"pop3s",
		"manage-sieve",
		"api",
		"web-dav",
	]);
	let names = srv_names(Services::from_config(&config));
	assert_eq!(names.len(), SrvService::ALL.len());
	for service in SrvService::ALL {
		let name = format!("{}._tcp.example.org", service.label());
		assert!(
			names.contains(&name),
			"{name} must be published when the service is on, got {names:?}"
		);
	}
}
