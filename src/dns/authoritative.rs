//! Asking the zone's own nameservers, with no cache in the way.
//!
//! A recursive resolver answers "no such name" from its cache for as long as
//! the zone's SOA allows (RFC 2308 section 5), so a record that is already
//! published stays invisible to a host whose resolver asked for the name
//! before it existed. Only the zone's own nameservers say what the zone
//! serves: they are asked directly, with recursion off and with no cache of
//! ours, so the answer is the zone's and not a copy of it.
//!
//! The nameservers of the closest enclosing zone are found through the host's
//! resolver (the delegation is the same everywhere), and each of them is then
//! asked at its own address.
//!
//! What a value found there means is the caller's question, not this one's:
//! the values come back as the servers served them, and the caller decides
//! which of them is the one it was looking for.

use std::net::IpAddr;
use std::pin::Pin;
use std::time::Duration;

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{RData, RecordType};

/// Per-query timeout when talking to one authoritative server.
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// What the zone's authoritative servers answer for a name.
pub type TxtLookup<'a> = Pin<Box<dyn Future<Output = Option<Authority>> + Send + 'a>>;

/// What the zone's authoritative servers answered for one name.
///
/// The servers are asked one by one, so `answers` holds one entry per server
/// that answered and `silent` says how many did not answer at all: a caller
/// that wants to know whether the whole zone serves the name has to compare
/// the two, because a server that said nothing proves nothing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Authority {
	/// How many servers were asked.
	pub servers: usize,
	/// The TXT values each server that answered returned.
	pub answers: Vec<Vec<String>>,
	/// How many of the servers did not answer at all.
	pub silent: usize,
}

impl Authority {
	/// Whether every server answered, and every answer holds a value `same`
	/// accepts.
	pub fn all_serve(&self, same: impl Fn(&str) -> bool) -> bool {
		self.servers > 0
			&& self.silent == 0
			&& self.answers.len() == self.servers
			&& self
				.answers
				.iter()
				.all(|values| values.iter().any(|v| same(v)))
	}

	/// Whether some server answered with a value `same` accepts.
	pub fn any_serve(&self, same: impl Fn(&str) -> bool) -> bool {
		self.answers
			.iter()
			.any(|values| values.iter().any(|v| same(v)))
	}
}

/// The zone's authoritative servers, asked for what they serve.
///
/// Behind a trait, so a caller with no network (a test, a command that must
/// not reach out) can answer with its own.
pub trait AuthorityLookup: Send + Sync {
	/// What the zone's authoritative servers answer for `name`. `None` when
	/// they could not be found; a server that did not answer is counted in
	/// [`Authority::silent`], because a silence says nothing about the zone.
	fn txt<'a>(&'a self, name: &'a str) -> TxtLookup<'a>;
}

/// The zone's authoritative servers, over the host's resolver.
pub struct SystemAuthority {
	resolver: TokioResolver,
}

impl SystemAuthority {
	/// Build on the system resolver (the same TCP-only configuration the rest
	/// of the server uses).
	pub fn from_system() -> std::io::Result<Self> {
		Ok(SystemAuthority {
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

/// The TXT values one server answers for `name`, or `None` when it did not
/// answer at all.
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
		.await;
	let answers = match lookup {
		Ok(lookup) => lookup,
		// The zone answered and denied the name: it holds no such TXT (or no
		// such name). That is an answer, not a silence, and it says the zone
		// does not serve the record.
		Err(hickory_resolver::net::NetError::Dns(
			hickory_resolver::net::DnsError::NoRecordsFound(_),
		)) => return Some(Vec::new()),
		// The server did not answer: a timeout, a refused connection, a
		// broken packet. Nothing is known about the zone.
		Err(_) => return None,
	};
	Some(
		answers
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

impl AuthorityLookup for SystemAuthority {
	fn txt<'a>(&'a self, name: &'a str) -> TxtLookup<'a> {
		Box::pin(async move {
			let servers = self.server_addresses(name).await;
			if servers.is_empty() {
				return None;
			}
			let mut answers = Vec::new();
			let mut silent = 0;
			for server in servers {
				match ask(server, name).await {
					Some(values) => answers.push(values),
					None => silent += 1,
				}
			}
			Some(Authority {
				servers: answers.len() + silent,
				answers,
				silent,
			})
		})
	}
}
