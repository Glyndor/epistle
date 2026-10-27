//! The service locators a deployment advertises. The set comes from the
//! listeners the configuration names, so a service the operator turned off
//! gets no SRV record and a client that follows a published locator always
//! reaches a listener.

use std::collections::BTreeSet;

use crate::config::{Config, ListenerKind};

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
}

/// The service locators a deployment advertises. The set follows the
/// configuration: a service the operator turned off gets no locator, so a
/// client that follows a published record reaches a listener. CalDAV and
/// CardDAV come from the `webdav` listener and JMAP from the `api` one.
/// The CAA record is separate: it comes from the `directory_url` of the
/// `acme` config section, and only when that directory names a CA we
/// recognise.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Services {
	/// The locators that are on.
	enabled: BTreeSet<SrvService>,
}

impl Services {
	/// Every locator on: the set of a deployment that exposes every service
	/// epistle serves.
	pub fn all() -> Self {
		Self {
			enabled: SrvService::ALL.into_iter().collect(),
		}
	}

	/// The locators the configuration's listeners enable. A listener the
	/// operator left out turns its locator off and one they added turns it
	/// on; the `webdav` listener brings CalDAV and CardDAV with it, and the
	/// `api` listener brings JMAP.
	pub fn from_config(config: &Config) -> Self {
		let mut enabled = BTreeSet::new();
		for listener in &config.listeners {
			match listener.kind {
				ListenerKind::Submission => {
					enabled.insert(SrvService::Submission);
				}
				ListenerKind::Submissions => {
					enabled.insert(SrvService::Submissions);
				}
				ListenerKind::Imap => {
					enabled.insert(SrvService::Imap);
				}
				ListenerKind::Imaps => {
					enabled.insert(SrvService::Imaps);
				}
				ListenerKind::Pop3s => {
					enabled.insert(SrvService::Pop3);
				}
				ListenerKind::ManageSieve => {
					enabled.insert(SrvService::Sieve);
				}
				ListenerKind::Api => {
					enabled.insert(SrvService::Jmap);
				}
				ListenerKind::WebDav => {
					enabled.insert(SrvService::Caldav);
					enabled.insert(SrvService::Carddav);
				}
				ListenerKind::Smtp
				| ListenerKind::Metrics
				| ListenerKind::Acme
				| ListenerKind::Autoconfig
				| ListenerKind::Autoconfigs => {}
			}
		}
		Self { enabled }
	}

	/// Whether the locator for `service` is advertised.
	pub fn contains(&self, service: SrvService) -> bool {
		self.enabled.contains(&service)
	}
}

#[cfg(test)]
#[path = "records_services_tests.rs"]
mod tests;
