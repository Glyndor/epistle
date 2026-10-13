//! DNS-01 propagation check against the zone's authoritative servers.
//!
//! A provider API accepting a record says nothing about when the zone's
//! name servers serve it, and the CA queries those servers (through its own
//! resolvers, which may hit any of them). Asking a recursive resolver would
//! be worse: it caches the NXDOMAIN from the first probe. So the check finds
//! the zone's NS set, resolves each server, and asks every address directly
//! with recursion off and no cache. The value is visible only when all of
//! them answer with it.
//!
//! This is network I/O glue, excluded from the no-network test suite; the
//! waiting and cleanup logic that uses it is tested with a fake.

use std::net::IpAddr;
use std::pin::Pin;
use std::time::Duration;

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{RData, RecordType};

use super::challenge::TxtVisibility;

/// Per-query timeout when talking to one authoritative server.
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Checks TXT visibility on the authoritative servers, finding them through
/// the host's resolver.
pub struct AuthoritativeTxt {
	resolver: TokioResolver,
}

impl AuthoritativeTxt {
	/// Build on the system resolver (the same TCP-only configuration the rest
	/// of the server uses).
	pub fn from_system() -> std::io::Result<Self> {
		Ok(AuthoritativeTxt {
			resolver: crate::spf::system_resolver()?,
		})
	}

	/// The NS host names of the closest enclosing zone of `name`.
	async fn zone_servers(&self, name: &str) -> Vec<String> {
		let mut candidate = name.trim_end_matches('.');
		loop {
			if let Ok(lookup) = self
				.resolver
				.lookup(format!("{candidate}."), RecordType::NS)
				.await
			{
				let hosts: Vec<String> = lookup
					.answers()
					.iter()
					.filter_map(|record| match &record.data {
						RData::NS(ns) => Some(ns.0.to_utf8()),
						_ => None,
					})
					.collect();
				if !hosts.is_empty() {
					return hosts;
				}
			}
			match candidate.split_once('.') {
				Some((_, parent)) if parent.contains('.') => candidate = parent,
				_ => return Vec::new(),
			}
		}
	}

	/// Every address of every authoritative server for `name`.
	async fn server_addresses(&self, name: &str) -> Vec<IpAddr> {
		let mut addresses = Vec::new();
		for host in self.zone_servers(name).await {
			if let Ok(lookup) = self.resolver.lookup_ip(host).await {
				addresses.extend(lookup.iter());
			}
		}
		addresses.sort();
		addresses.dedup();
		addresses
	}
}

/// TXT values one server returns for `name`, or `None` when it did not answer.
async fn ask(server: IpAddr, name: &str) -> Option<Vec<String>> {
	let config = ResolverConfig::from_parts(
		None,
		Vec::new(),
		vec![NameServerConfig::udp_and_tcp(server)],
	);
	let mut builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
	let options = builder.options_mut();
	options.recursion_desired = false;
	options.cache_size = 0;
	options.timeout = QUERY_TIMEOUT;
	options.attempts = 1;
	let resolver = builder.build().ok()?;
	let lookup = resolver
		.lookup(format!("{}.", name.trim_end_matches('.')), RecordType::TXT)
		.await
		.ok()?;
	Some(
		lookup
			.answers()
			.iter()
			.filter_map(|record| match &record.data {
				RData::TXT(txt) => Some(
					txt.txt_data
						.iter()
						.map(|chunk| String::from_utf8_lossy(chunk).to_string())
						.collect::<String>(),
				),
				_ => None,
			})
			.collect(),
	)
}

impl TxtVisibility for AuthoritativeTxt {
	fn visible<'a>(
		&'a self,
		name: &'a str,
		value: &'a str,
	) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
		Box::pin(async move {
			let servers = self.server_addresses(name).await;
			if servers.is_empty() {
				return false;
			}
			for server in servers {
				match ask(server, name).await {
					Some(values) if values.iter().any(|v| v == value) => {}
					_ => return false,
				}
			}
			true
		})
	}
}
