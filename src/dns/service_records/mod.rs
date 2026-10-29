//! The service records a deployment advertises. The set comes from the
//! listeners the configuration names, so a service the operator turned off
//! gets no SRV record and a client that follows a published locator always
//! reaches a listener. The names that reach the client setup documents
//! follow the same rule: they are published when a listener serves those
//! documents.

use std::collections::{BTreeMap, BTreeSet};

use crate::config::{Config, Listener, ListenerKind};
use crate::dns::provider::{DnsRecord, RecordKind};
use crate::dns::records::PublishRecord;

/// A service epistle can advertise a locator for. The variant names the SRV
/// owner label and the port the locator points at; whether the record is
/// published follows the configuration, so a client that follows a published
/// locator reaches a listener.
///
/// Per RFC 6186 (IMAP/POP3/SUBMISSION), RFC 8314 (Implicit TLS), RFC 8621
/// (JMAP) and ManageSieve (RFC 5804).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SrvService {
	/// Submission over implicit TLS (port 465).
	Submissions,
	/// Submission with STARTTLS (port 587).
	Submission,
	/// IMAP over implicit TLS (port 993).
	Imaps,
	/// IMAP with STARTTLS (port 143).
	Imap,
	/// POP3 over implicit TLS (port 995).
	Pop3,
	/// JMAP (port 443), served by the `api` listener.
	Jmap,
	/// ManageSieve (port 4190).
	Sieve,
	/// CalDAV (port 443), served by the `webdav` listener.
	Caldav,
	/// CardDAV (port 443), served by the `webdav` listener.
	Carddav,
}

impl SrvService {
	/// Every locator epistle knows, in the order the records are published.
	pub const ALL: [SrvService; 9] = [
		SrvService::Submissions,
		SrvService::Submission,
		SrvService::Imaps,
		SrvService::Imap,
		SrvService::Pop3,
		SrvService::Jmap,
		SrvService::Sieve,
		SrvService::Caldav,
		SrvService::Carddav,
	];

	/// The SRV owner label, without the `_tcp` part.
	pub const fn label(self) -> &'static str {
		match self {
			SrvService::Submissions => "_submissions",
			SrvService::Submission => "_submission",
			SrvService::Imaps => "_imaps",
			SrvService::Imap => "_imap",
			SrvService::Pop3 => "_pop3s",
			SrvService::Jmap => "_jmap",
			SrvService::Sieve => "_sieve",
			SrvService::Caldav => "_caldavs",
			SrvService::Carddav => "_carddavs",
		}
	}

	/// The port the locator points at.
	pub const fn port(self) -> u16 {
		match self {
			SrvService::Submissions => 465,
			SrvService::Submission => 587,
			SrvService::Imaps => 993,
			SrvService::Imap => 143,
			SrvService::Pop3 => 995,
			SrvService::Jmap => 443,
			SrvService::Sieve => 4190,
			SrvService::Caldav => 443,
			SrvService::Carddav => 443,
		}
	}

	/// The services a listener kind exposes. A listener the operator left
	/// out takes its services with it, and a listener of a kind that serves
	/// no locator (SMTP, metrics, ACME, autodiscovery) exposes none.
	pub const fn of_listener(kind: ListenerKind) -> &'static [SrvService] {
		match kind {
			ListenerKind::Submission => &[SrvService::Submission],
			ListenerKind::Submissions => &[SrvService::Submissions],
			ListenerKind::Imap => &[SrvService::Imap],
			ListenerKind::Imaps => &[SrvService::Imaps],
			ListenerKind::Pop3s => &[SrvService::Pop3],
			ListenerKind::ManageSieve => &[SrvService::Sieve],
			ListenerKind::Api => &[SrvService::Jmap],
			// Both DAV services share the listener; there is no flag that
			// turns one of them off.
			ListenerKind::WebDav => &[SrvService::Caldav, SrvService::Carddav],
			ListenerKind::Smtp
			| ListenerKind::Metrics
			| ListenerKind::Acme
			| ListenerKind::Autoconfig
			| ListenerKind::Autoconfigs => &[],
		}
	}

	/// The port the locator of this service names for a listener that binds
	/// `listener`.
	///
	/// The mail protocols name the port their listener binds, so a client
	/// that follows the locator reaches the listener that serves it. JMAP
	/// and the DAV services do not: they are served over internal HTTP and
	/// reached through the public HTTPS endpoint of the deployment, so their
	/// locator names port 443 whatever the listener binds (8025 and 8090 by
	/// default).
	fn port_for(self, listener: &Listener) -> u16 {
		match self {
			SrvService::Jmap | SrvService::Caldav | SrvService::Carddav => self.port(),
			SrvService::Submissions
			| SrvService::Submission
			| SrvService::Imaps
			| SrvService::Imap
			| SrvService::Pop3
			| SrvService::Sieve => listener.socket_addr().port(),
		}
	}
}

/// The service records a deployment advertises. The set follows the
/// configuration: a service the operator turned off gets no locator, so a
/// client that follows a published record reaches a listener. Each locator
/// names the port its listener binds, and the same service announced on
/// IPv4 and on IPv6 is one locator, not two.
///
/// CalDAV and CardDAV come from the `webdav` listener and JMAP from the
/// `api` one, which needs an API to point a client at. The names that reach
/// the client setup documents come from the `autoconfig` and `autoconfigs`
/// listeners. The CAA record is separate: it comes from the `directory_url`
/// of the `acme` config section, and only when that directory names a CA we
/// recognise.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceRecords {
	/// The locators that are on: the service, and the ports it names.
	locators: BTreeMap<SrvService, BTreeSet<u16>>,
	/// Whether the deployment serves the client setup documents, and the
	/// names that reach them are published.
	autodiscovery: bool,
}

impl ServiceRecords {
	/// The records the configuration's listeners enable. A listener the
	/// operator left out turns its service off and one they added turns it
	/// on; the `webdav` listener brings CalDAV and CardDAV with it, and the
	/// `api` listener brings JMAP when the configuration carries the API
	/// that serves it.
	pub fn from_config(config: &Config) -> Self {
		let mut locators: BTreeMap<SrvService, BTreeSet<u16>> = BTreeMap::new();
		let mut autodiscovery = false;
		for listener in &config.listeners {
			// The client setup documents are served by these two listeners
			// and by nothing else, so the names that reach them are
			// published only when one of them is on.
			if matches!(
				listener.kind,
				ListenerKind::Autoconfig | ListenerKind::Autoconfigs
			) {
				autodiscovery = true;
			}
			// JMAP lives in the API router, so it needs an API to point a
			// client at. A configuration that names the listener without
			// the section is one the loader refuses, and one that names no
			// API has no JMAP session to publish.
			if listener.kind == ListenerKind::Api && config.api.is_none() {
				continue;
			}
			for service in SrvService::of_listener(listener.kind) {
				locators
					.entry(*service)
					.or_default()
					.insert(service.port_for(listener));
			}
		}
		Self {
			locators,
			autodiscovery,
		}
	}

	/// Whether the locator for `service` is advertised.
	pub fn contains(&self, service: SrvService) -> bool {
		self.locators.contains_key(&service)
	}

	/// The locators, in the order the records are published: by service,
	/// and by port within a service.
	pub fn locators(&self) -> impl Iterator<Item = (SrvService, u16)> + '_ {
		self.locators
			.iter()
			.flat_map(|(service, ports)| ports.iter().map(move |port| (*service, *port)))
	}

	/// Whether the deployment serves the client setup documents, and the
	/// names that reach them are published. A deployment that serves none
	/// publishes neither name: a client that follows one of them would
	/// reach nothing.
	pub fn advertises_autodiscovery(&self) -> bool {
		self.autodiscovery
	}
}

/// The SRV records one domain gets: one per locator the deployment
/// advertises. The locator names the port the service is reached at, so a
/// client that follows the record reaches a listener.
pub fn service_records(
	services: &ServiceRecords,
	domain: &str,
	hostname: &str,
) -> Vec<PublishRecord> {
	services
		.locators()
		.map(|(service, port)| PublishRecord {
			zone: domain.to_string(),
			record: DnsRecord {
				name: format!("{}._tcp.{domain}", service.label()),
				kind: RecordKind::Srv,
				value: format!("0 1 {port} {hostname}."),
				ttl: crate::dns::records::TTL,
				proxied: None,
			},
		})
		.collect()
}

#[cfg(test)]
mod tests;
