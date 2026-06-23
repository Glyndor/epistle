//! DNS access for SPF evaluation, behind a trait for testability.

use std::net::IpAddr;
use std::pin::Pin;

use crate::dane::tlsa::TlsaRecord;

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
	/// DNSSEC-validated TLSA records of a name (the full owner name, e.g.
	/// `_25._tcp.mx.example.com`).
	///
	/// DANE MUST NOT trust unvalidated TLSA (RFC 7672 §2.1): an implementation
	/// returns records only when the DNS response was authenticated (DNSSEC
	/// "secure"). When the response is unvalidated, the name does not exist, or
	/// no records are published, this returns an empty vector — the caller then
	/// treats the host as having no DANE policy (opportunistic TLS). The default
	/// implementation returns no records, so a resolver without DNSSEC support
	/// never enables DANE enforcement.
	fn tlsa(&self, _name: &str) -> Lookup<'_, Vec<TlsaRecord>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

/// Real resolver on top of hickory.
pub struct SystemDns {
	resolver: hickory_resolver::TokioResolver,
}

impl SystemDns {
	/// Build from the system DNS configuration, with DNSSEC validation enabled.
	///
	/// Validation is required so DANE can trust TLSA records (RFC 7672 §2.1):
	/// the resolver authenticates responses against the IANA root trust anchor
	/// and stamps each answer with its DNSSEC proof. Validation needs an
	/// upstream resolver that returns DNSSEC records (the EDNS DO bit is set);
	/// against a non-validating-aware path, answers come back unauthenticated
	/// and TLSA lookups yield nothing, so DANE simply does not engage.
	pub fn from_system() -> std::io::Result<Self> {
		let mut builder =
			hickory_resolver::TokioResolver::builder_tokio().map_err(std::io::Error::other)?;
		builder.options_mut().validate = true;
		Ok(SystemDns {
			resolver: builder.build().map_err(std::io::Error::other)?,
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

	fn tlsa(&self, name: &str) -> Lookup<'_, Vec<TlsaRecord>> {
		let name = name.to_string();
		Box::pin(async move {
			use hickory_resolver::net::{DnsError, NetError};
			use hickory_resolver::proto::rr::{RData, RecordType};
			let lookup = match self
				.resolver
				.lookup(format!("{name}."), RecordType::TLSA)
				.await
			{
				Ok(lookup) => lookup,
				Err(NetError::Dns(DnsError::NoRecordsFound(_))) => return Ok(Vec::new()),
				Err(_) => return Err(DnsFailure::Temporary),
			};
			// Only DNSSEC-"secure" answers may be trusted for DANE (RFC 7672
			// §2.1). A record whose proof is anything else (insecure, bogus,
			// indeterminate) is dropped, so an unvalidated zone yields no TLSA
			// and DANE does not engage — fail open to opportunistic TLS, never
			// trust unauthenticated association data.
			Ok(lookup
				.answers()
				.iter()
				.filter(|record| record.proof.is_secure())
				.filter_map(|record| match &record.data {
					RData::TLSA(tlsa) => TlsaRecord::from_parts(
						u8::from(tlsa.cert_usage),
						u8::from(tlsa.selector),
						u8::from(tlsa.matching),
						tlsa.cert_data.clone(),
					),
					_ => None,
				})
				.collect())
		})
	}
}
