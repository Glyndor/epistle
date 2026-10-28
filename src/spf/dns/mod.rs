//! DNS access for SPF evaluation, behind a trait for testability.

use std::net::IpAddr;
use std::pin::Pin;

use hickory_resolver::config::{ProtocolConfig, ResolveHosts, ResolverConfig, ResolverOpts};

use crate::dane::rrset::TlsaRrset;

#[cfg(test)]
mod tests;

/// Build a `ResolverConfig` from the system configuration (`/etc/resolv.conf`
/// on Unix, the registry on Windows) keeping only the TCP connection of each
/// name server. The UDP connection is dropped because, behind
/// systemd-resolved's stub, a DNSSEC-validating reply can come back truncated
/// to the EDNS UDP size and hickory decodes the whole UDP message before
/// noticing the TC bit, so the lookup fails without ever retrying over TCP.
pub(crate) fn system_resolver_config() -> std::io::Result<ResolverConfig> {
	let (config, _opts) =
		hickory_resolver::system_conf::read_system_conf().map_err(std::io::Error::other)?;
	Ok(keep_only_tcp(config))
}

/// Build the resolver options the system resolver uses: defaults from
/// `/etc/resolv.conf`, DNSSEC validation enabled, and the hosts file never
/// consulted. The lookups made here (SPF, MX, DANE, `verify-dns`, the PTR
/// check of `init`) are about what the world sees, so a line in
/// `/etc/hosts` must not answer them.
pub(crate) fn system_resolver_options() -> ResolverOpts {
	let (_config, mut opts) = hickory_resolver::system_conf::read_system_conf()
		.map_err(std::io::Error::other)
		.unwrap();
	opts.validate = true;
	opts.use_hosts_file = ResolveHosts::Never;
	opts
}

fn keep_only_tcp(mut config: ResolverConfig) -> ResolverConfig {
	for server in &mut config.name_servers {
		server.connections = server
			.connections
			.iter()
			.filter(|connection| matches!(connection.protocol, ProtocolConfig::Tcp))
			.cloned()
			.collect();
	}
	config
}

/// Build a `TokioResolver` from the system configuration, TCP-only, with
/// DNSSEC validation enabled. Every hickory resolver that resolves names
/// from the host (`SystemDns` for SPF, `MxConnector` for the queue) goes
/// through this so the systemd-resolved truncation workaround stays in one
/// place.
pub fn system_resolver() -> std::io::Result<hickory_resolver::TokioResolver> {
	build_resolver(system_resolver_config()?, system_resolver_options())
}

fn build_resolver(
	config: ResolverConfig,
	opts: ResolverOpts,
) -> std::io::Result<hickory_resolver::TokioResolver> {
	let mut builder = hickory_resolver::TokioResolver::builder_with_config(
		config,
		hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
	);
	*builder.options_mut() = opts;
	builder.build().map_err(std::io::Error::other)
}

/// A DNS query failure as SPF distinguishes them (RFC 7208 section 2.6.6/7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsFailure {
	/// Transient lookup problem: evaluation yields `temperror`.
	Temporary,
}

type LookupResult<T> = Result<T, DnsFailure>;
type Lookup<'a, T> = Pin<Box<dyn Future<Output = LookupResult<T>> + Send + 'a>>;

/// The queries SPF evaluation needs. Nonexistent names return empty vectors,
/// not errors.
pub trait DnsLookup: Send + Sync {
	/// TXT records of a name.
	fn txt(&self, name: &str) -> Lookup<'_, Vec<String>>;
	/// A/AAAA addresses of a name.
	fn addresses(&self, name: &str) -> Lookup<'_, Vec<IpAddr>>;
	/// MX exchange hostnames of a name.
	fn mx(&self, name: &str) -> Lookup<'_, Vec<String>>;
	/// The TLSA RRset of a name (the full owner name, e.g.
	/// `_25._tcp.mx.example.com`), classified by
	/// [`crate::dane::rrset::classify`].
	///
	/// DANE MUST NOT trust unvalidated TLSA (RFC 7672 §2.1): records count
	/// only when the DNS response was authenticated (DNSSEC "secure"). The
	/// default implementation reports no RRset, so a resolver without DNSSEC
	/// support never enables DANE enforcement.
	fn tlsa(&self, _name: &str) -> Lookup<'_, TlsaRrset> {
		Box::pin(async { Ok(TlsaRrset::Absent) })
	}
	/// PTR (reverse DNS) records for an IP address: every name the address
	/// points at, in lower case without a trailing dot. A reverse lookup that
	/// yields no answer returns an empty vector, not an error. The default
	/// implementation returns no records so a fixture that does not care
	/// about reverse DNS keeps compiling.
	fn ptr(&self, _ip: IpAddr) -> Lookup<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

/// Real resolver on top of hickory.
pub struct SystemDns {
	resolver: hickory_resolver::TokioResolver,
	/// The same name servers without DNSSEC validation, for PTR only (see
	/// [`DnsLookup::ptr`] below).
	reverse: hickory_resolver::TokioResolver,
}

impl SystemDns {
	/// Build from the system DNS configuration. Goes through the shared
	/// `system_resolver` so the TCP-only + DNSSEC contract stays in one place.
	///
	/// Validation is required so DANE can trust TLSA records (RFC 7672 §2.1):
	/// the resolver authenticates responses against the IANA root trust anchor
	/// and stamps each answer with its DNSSEC proof. Validation needs an
	/// upstream resolver that returns DNSSEC records (the EDNS DO bit is set);
	/// against a non-validating-aware path, answers come back unauthenticated
	/// and TLSA lookups yield nothing, so DANE simply does not engage.
	pub fn from_system() -> std::io::Result<Self> {
		Self::with_config(system_resolver_config()?, system_resolver_options())
	}

	/// Like [`Self::from_system`], without the resolver's answer cache:
	/// for a caller that polls for a record it just published, where a
	/// cached "no such name" would hide the record for its whole TTL.
	pub fn uncached_from_system() -> std::io::Result<Self> {
		let mut opts = system_resolver_options();
		opts.cache_size = 0;
		Self::with_config(system_resolver_config()?, opts)
	}

	/// Build over explicit name servers and options; [`Self::from_system`]
	/// passes the host's.
	pub(crate) fn with_config(config: ResolverConfig, opts: ResolverOpts) -> std::io::Result<Self> {
		let mut reverse_opts = opts.clone();
		reverse_opts.validate = false;
		Ok(SystemDns {
			resolver: build_resolver(config.clone(), opts)?,
			reverse: build_resolver(config, reverse_opts)?,
		})
	}

	async fn lookup(
		&self,
		name: &str,
		record_type: hickory_resolver::proto::rr::RecordType,
	) -> LookupResult<Vec<hickory_resolver::proto::rr::RData>> {
		use hickory_resolver::net::{DnsError, NetError};
		match self.resolver.lookup(format!("{name}."), record_type).await {
			Ok(lookup) => Ok(lookup
				.answers()
				.iter()
				.map(|record| record.data.clone())
				.collect()),
			Err(NetError::Dns(DnsError::NoRecordsFound(_))) => Ok(Vec::new()),
			Err(_) => Err(DnsFailure::Temporary),
		}
	}
}

impl DnsLookup for SystemDns {
	fn txt(&self, name: &str) -> Lookup<'_, Vec<String>> {
		let name = name.to_string();
		Box::pin(async move {
			use hickory_resolver::proto::rr::{RData, RecordType};
			let records = self.lookup(&name, RecordType::TXT).await?;
			Ok(records
				.iter()
				.filter_map(|data| match data {
					RData::TXT(txt) => Some(
						txt.txt_data
							.iter()
							.map(|chunk| String::from_utf8_lossy(chunk).to_string())
							.collect::<Vec<_>>()
							.concat(),
					),
					_ => None,
				})
				.collect())
		})
	}

	fn addresses(&self, name: &str) -> Lookup<'_, Vec<IpAddr>> {
		let name = name.to_string();
		Box::pin(async move {
			use hickory_resolver::net::{DnsError, NetError};
			match self.resolver.lookup_ip(format!("{name}.")).await {
				Ok(lookup) => Ok(lookup.iter().collect()),
				Err(NetError::Dns(DnsError::NoRecordsFound(_))) => Ok(Vec::new()),
				Err(_) => Err(DnsFailure::Temporary),
			}
		})
	}

	fn mx(&self, name: &str) -> Lookup<'_, Vec<String>> {
		let name = name.to_string();
		Box::pin(async move {
			use hickory_resolver::proto::rr::{RData, RecordType};
			let records = self.lookup(&name, RecordType::MX).await?;
			Ok(records
				.iter()
				.filter_map(|data| match data {
					RData::MX(mx) => Some(mx.exchange.to_utf8().trim_end_matches('.').to_string()),
					_ => None,
				})
				.collect())
		})
	}

	fn tlsa(&self, name: &str) -> Lookup<'_, TlsaRrset> {
		let name = name.to_string();
		Box::pin(async move {
			use crate::dane::rrset::{TlsaAnswer, Validation};
			use hickory_resolver::net::{DnsError, NetError};
			use hickory_resolver::proto::dnssec::Proof;
			use hickory_resolver::proto::rr::{RData, RecordType};
			let lookup = match self
				.resolver
				.lookup(format!("{name}."), RecordType::TLSA)
				.await
			{
				Ok(lookup) => lookup,
				Err(NetError::Dns(DnsError::NoRecordsFound(_))) => return Ok(TlsaRrset::Absent),
				Err(_) => return Err(DnsFailure::Temporary),
			};
			let answers: Vec<TlsaAnswer> = lookup
				.answers()
				.iter()
				.filter_map(|record| match &record.data {
					RData::TLSA(tlsa) => Some(TlsaAnswer {
						validation: match record.proof {
							Proof::Secure => Validation::Secure,
							Proof::Insecure => Validation::Insecure,
							Proof::Bogus => Validation::Bogus,
							Proof::Indeterminate => Validation::Indeterminate,
						},
						usage: u8::from(tlsa.cert_usage),
						selector: u8::from(tlsa.selector),
						matching_type: u8::from(tlsa.matching),
						data: tlsa.cert_data.clone(),
					}),
					_ => None,
				})
				.collect();
			crate::dane::rrset::classify(&answers)
		})
	}

	/// Unvalidated: nothing trusts a PTR because of DNSSEC (the name is
	/// only believed once it resolves back), most of the reverse tree is
	/// unsigned, and hickory reports some unsigned `ip6.arpa` answers as
	/// bogus, which turned every such IPv6 lookup into a failure.
	fn ptr(&self, ip: IpAddr) -> Lookup<'_, Vec<String>> {
		Box::pin(async move {
			use hickory_resolver::net::{DnsError, NetError};
			use hickory_resolver::proto::rr::RData;
			match self.reverse.reverse_lookup(ip).await {
				Ok(lookup) => Ok(lookup
					.answers()
					.iter()
					.filter_map(|record| match &record.data {
						RData::PTR(ptr) => {
							Some(ptr.0.to_utf8().trim_end_matches('.').to_ascii_lowercase())
						}
						_ => None,
					})
					.collect()),
				Err(NetError::Dns(DnsError::NoRecordsFound(_))) => Ok(Vec::new()),
				Err(_) => Err(DnsFailure::Temporary),
			}
		})
	}
}
