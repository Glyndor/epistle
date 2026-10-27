//! `verify-dns` never asks the resolver for the locator of a service the
//! configuration leaves off, and never reports one as missing.
//!
//! A locator names a port the deployment answers on. Asking about the
//! locator of a service nobody listens on either sends the operator after
//! a record they never had to publish, or hides a real drift behind a
//! check that does not apply.

use super::*;
use crate::spf::DnsFailure;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Mutex;

/// A resolver that records every name it is asked about.
#[derive(Default)]
struct RecordingDns {
	queried: Mutex<Vec<String>>,
}

impl RecordingDns {
	/// Whether the resolver was asked about this name.
	fn asked(&self, name: &str) -> bool {
		self.queried
			.lock()
			.expect("lock")
			.iter()
			.any(|queried| queried == name)
	}
}

impl DnsLookup for RecordingDns {
	fn txt(
		&self,
		name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		self.queried.lock().expect("lock").push(name.to_string());
		Box::pin(async move { Ok(Vec::new()) })
	}
	fn addresses(
		&self,
		name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, DnsFailure>> + Send + '_>> {
		self.queried.lock().expect("lock").push(name.to_string());
		Box::pin(async move { Ok(Vec::new()) })
	}
	fn mx(
		&self,
		name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		self.queried.lock().expect("lock").push(name.to_string());
		Box::pin(async move { Ok(Vec::new()) })
	}
}

/// A configuration with the given listeners and one hosted domain.
fn config_with(listeners: &[&str]) -> Config {
	let mut toml = String::from(
		"hostname = 'mail.example.org'\ndata_dir = '/var/lib/mail'\ndomains = ['example.org']\n",
	);
	for kind in listeners {
		toml.push_str(&format!("\n[[listeners]]\nkind = '{kind}'\n"));
	}
	toml::from_str(&toml).expect("config")
}

/// The locators of the services the configuration leaves off.
const OFF: [&str; 5] = [
	"_pop3s._tcp",
	"_jmap._tcp",
	"_sieve._tcp",
	"_caldavs._tcp",
	"_carddavs._tcp",
];

#[tokio::test]
async fn a_disabled_service_is_never_asked_for() {
	let dns = RecordingDns::default();
	let mut out = Vec::new();
	let config = config_with(&["imap", "imaps", "submission"]);
	let _ = report(
		&["example.org".to_string()],
		"mail.example.org",
		None,
		None,
		&dns,
		&config,
		(false, &mut out),
		crate::cli::style::Progress::start("checking"),
	)
	.await;
	for locator in OFF {
		let name = format!("{locator}.example.org");
		assert!(
			!dns.asked(&name),
			"verify-dns must not ask about {name}: the service is off"
		);
	}
	let text = String::from_utf8(out).expect("utf-8");
	for locator in OFF {
		assert!(
			!text.contains(locator),
			"verify-dns must not report {locator} as missing: {text}"
		);
	}
}
