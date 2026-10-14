//! Connecting to the responsible server for a recipient domain.

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::mtasts::Policy;

use super::client::DeliveryError;
use super::limits::{MAX_ADDRESSES, MAX_EXCHANGERS};
use super::timeouts;

/// A bidirectional stream the SMTP client can drive.
pub type BoxedStream = Box<dyn DynStream>;

/// Future returned by [`Connector::connect`].
pub type ConnectFuture<'a> =
	std::pin::Pin<Box<dyn Future<Output = Result<Connection, DeliveryError>> + Send + 'a>>;

/// An open connection to one exchanger of a domain.
pub struct Connection {
	/// The stream the SMTP client drives.
	pub stream: BoxedStream,
	/// The exchanger's host name (TLS server name, DANE/TLSA owner).
	pub host: String,
	/// Our side of the connection, when the transport knows it. TLS-RPT
	/// reports it as `sending-mta-ip`.
	pub local_ip: Option<std::net::IpAddr>,
	/// The exchanger's address, when the transport knows it.
	pub peer_ip: Option<std::net::IpAddr>,
	/// Whether the MX answer that named this host was DNSSEC-secure.
	pub mx: MxSecurity,
}

/// The DNSSEC state of the MX lookup that named an exchanger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MxSecurity {
	/// Every MX record validated.
	Secure,
	/// The answer was unsigned, or there was no MX record to validate.
	Insecure,
}

/// The DNSSEC state of an MX answer from the validation proof of each
/// record. A record that failed validation fails the lookup, as RFC 7672
/// section 2.1.1 asks of any bogus answer; the answer is secure only
/// when there are records and every one of them validated.
pub(crate) fn mx_security(
	proofs: impl IntoIterator<Item = hickory_resolver::proto::dnssec::Proof>,
) -> Result<MxSecurity, crate::spf::DnsFailure> {
	use hickory_resolver::proto::dnssec::Proof;
	let mut secure = None;
	for proof in proofs {
		match proof {
			Proof::Bogus => return Err(crate::spf::DnsFailure::Temporary),
			Proof::Secure => secure = Some(secure.unwrap_or(true)),
			Proof::Insecure | Proof::Indeterminate => secure = Some(false),
		}
	}
	Ok(if secure == Some(true) {
		MxSecurity::Secure
	} else {
		MxSecurity::Insecure
	})
}

/// The DNSSEC state of an implicit MX (RFC 7672 sections 2.2.1 and
/// 2.2.2): the domain has no MX, and `denial` and `address` are the
/// validation proofs of that denial and of the domain's address answer.
/// Secure only when both are; a bogus side fails the lookup, so the
/// message waits; anything unsigned or unanchored is insecure.
pub(crate) fn implicit_mx_security(
	denial: hickory_resolver::proto::dnssec::Proof,
	address: hickory_resolver::proto::dnssec::Proof,
) -> Result<MxSecurity, crate::spf::DnsFailure> {
	use hickory_resolver::proto::dnssec::Proof;
	if denial == Proof::Bogus || address == Proof::Bogus {
		return Err(crate::spf::DnsFailure::Temporary);
	}
	Ok(if denial == Proof::Secure && address == Proof::Secure {
		MxSecurity::Secure
	} else {
		MxSecurity::Insecure
	})
}

/// One proof for a set of records: bogus if any is, secure if there are
/// some and all are, insecure otherwise.
fn summarize(
	proofs: impl IntoIterator<Item = hickory_resolver::proto::dnssec::Proof>,
) -> hickory_resolver::proto::dnssec::Proof {
	use hickory_resolver::proto::dnssec::Proof;
	let mut summary = None;
	for proof in proofs {
		summary = Some(match (summary, proof) {
			(_, Proof::Bogus) | (Some(Proof::Bogus), _) => Proof::Bogus,
			(None | Some(Proof::Secure), Proof::Secure) => Proof::Secure,
			_ => Proof::Insecure,
		});
	}
	summary.unwrap_or(Proof::Insecure)
}

impl Connection {
	/// A connection over a transport without socket addresses.
	pub fn new(stream: BoxedStream, host: String) -> Self {
		Connection {
			stream,
			host,
			local_ip: None,
			peer_ip: None,
			mx: MxSecurity::Insecure,
		}
	}

	/// Record the DNSSEC state of the MX answer that named this host.
	pub fn with_mx(mut self, mx: MxSecurity) -> Self {
		self.mx = mx;
		self
	}
}

/// Object-safe stream alias.
pub trait DynStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> DynStream for T {}

/// Opens a connection to the mail exchanger of a domain. Abstracted so the
/// worker can be tested without DNS or network access.
pub trait Connector: Send + Sync {
	/// Connect to an exchanger for `domain`. With an enforce-mode policy,
	/// only policy-permitted MX hosts may be contacted.
	fn connect(&self, domain: &str, policy: Option<&Policy>) -> ConnectFuture<'_>;

	/// Connect to the next exchanger for `domain`, leaving out the hosts in
	/// `tried`, which already failed this delivery attempt. A connector
	/// that only knows one way in has nothing after the first.
	fn connect_skipping(
		&self,
		domain: &str,
		policy: Option<&Policy>,
		tried: &[String],
	) -> ConnectFuture<'_> {
		if tried.is_empty() {
			return self.connect(domain, policy);
		}
		let domain = domain.to_string();
		Box::pin(async move {
			Err(DeliveryError::Transient(format!(
				"no further exchanger for {domain}"
			)))
		})
	}
}

/// Real connector: system resolver for MX records, TCP to port 25.
pub struct MxConnector {
	resolver: hickory_resolver::TokioResolver,
}

impl MxConnector {
	/// Build a connector using the system DNS configuration. Goes through the
	/// shared `system_resolver` so the TCP-only + DNSSEC contract stays in
	/// one place (see `crate::spf::system_resolver` for the rationale).
	pub fn from_system() -> std::io::Result<Self> {
		Ok(MxConnector {
			resolver: crate::spf::system_resolver()?,
		})
	}

	/// MX hostnames in preference order; implicit MX (the domain itself,
	/// RFC 5321 section 5.1) when no MX records exist.
	async fn exchangers(&self, domain: &str) -> Result<(Vec<String>, MxSecurity), DeliveryError> {
		use hickory_resolver::net::{DnsError, NetError};
		use hickory_resolver::proto::rr::{RecordType, rdata::MX};

		match self
			.resolver
			.lookup(format!("{domain}."), RecordType::MX)
			.await
		{
			Ok(lookup) => {
				let mut records: Vec<&MX> = lookup
					.answers()
					.iter()
					.filter_map(|record| match &record.data {
						hickory_resolver::proto::rr::RData::MX(mx) => Some(mx),
						_ => None,
					})
					.collect();
				let security = mx_security(lookup.answers().iter().map(|record| record.proof))
					.map_err(|_| {
						DeliveryError::Transient(format!(
							"MX answer for {domain} failed DNSSEC validation"
						))
					})?;
				records.sort_by_key(|mx| mx.preference);
				let records: Vec<(u16, String)> = records
					.iter()
					.map(|mx| (mx.preference, mx.exchange.to_utf8()))
					.collect();
				// With no exchange to name, the domain itself is the implicit
				// MX, which no validated MX record vouches for.
				let named = records
					.iter()
					.any(|(_, exchange)| !exchange.trim_end_matches('.').is_empty());
				let hosts = exchangers_from(domain, records)?;
				Ok((
					hosts,
					if named {
						security
					} else {
						MxSecurity::Insecure
					},
				))
			}
			// No MX records: fall back to the implicit MX, as secure as the
			// denial and the domain's own address answer prove it to be.
			Err(NetError::Dns(DnsError::NoRecordsFound(no_records))) => {
				let denial = summarize(no_records.soa.iter().map(|soa| soa.proof).chain(
					no_records.authorities.iter().flat_map(|records| {
						records
							.iter()
							.map(|record| record.proof)
							.collect::<Vec<_>>()
					}),
				));
				self.implicit(domain, denial).await
			}
			Err(NetError::Dns(DnsError::Nsec { proof, .. })) => self.implicit(domain, proof).await,
			Err(NetError::Dns(DnsError::DnssecBogus)) => Err(DeliveryError::Transient(format!(
				"MX answer for {domain} failed DNSSEC validation"
			))),
			Err(error) => Err(DeliveryError::Transient(format!(
				"MX lookup failed: {error}"
			))),
		}
	}
}

/// The exchangers of `domain` from its MX records (preference, exchange
/// name), sorted by preference; the domain itself (implicit MX, RFC 5321
/// §5.1) when there are none.
///
/// A sole MX naming the root (`0 .`) is a null MX (RFC 7505): the domain
/// accepts no mail, so delivery fails at once with 556 5.1.10, a bad
/// address, instead of being retried against an empty host name. A root
/// exchange next to real ones is a misconfiguration and is skipped.
fn exchangers_from(
	domain: &str,
	records: Vec<(u16, String)>,
) -> Result<Vec<String>, DeliveryError> {
	let null = records.len() == 1 && records[0].1.trim_end_matches('.').is_empty();
	if null {
		return Err(DeliveryError::Permanent(format!(
			"556 5.1.10 {domain} accepts no mail (null MX)"
		)));
	}
	let hosts: Vec<String> = records
		.into_iter()
		.map(|(_, exchange)| exchange.trim_end_matches('.').to_string())
		.filter(|host| !host.is_empty())
		.collect();
	if hosts.is_empty() {
		Ok(vec![domain.to_string()])
	} else {
		Ok(hosts)
	}
}

impl MxConnector {
	/// The implicit MX of `domain`, given how its MX denial validated.
	async fn implicit(
		&self,
		domain: &str,
		denial: hickory_resolver::proto::dnssec::Proof,
	) -> Result<(Vec<String>, MxSecurity), DeliveryError> {
		let address = self.address_proof(domain).await;
		match implicit_mx_security(denial, address) {
			Ok(security) => Ok((vec![domain.to_string()], security)),
			Err(_) => Err(DeliveryError::Transient(format!(
				"implicit MX of {domain} failed DNSSEC validation"
			))),
		}
	}

	/// How the A and AAAA answers of `host` validated, together.
	async fn address_proof(&self, host: &str) -> hickory_resolver::proto::dnssec::Proof {
		use hickory_resolver::net::{DnsError, NetError};
		use hickory_resolver::proto::dnssec::Proof;
		use hickory_resolver::proto::rr::RecordType;
		let mut proofs = Vec::new();
		for kind in [RecordType::A, RecordType::AAAA] {
			match self.resolver.lookup(format!("{host}."), kind).await {
				Ok(lookup) => proofs.extend(lookup.answers().iter().map(|record| record.proof)),
				Err(NetError::Dns(DnsError::NoRecordsFound(_))) => {}
				Err(NetError::Dns(DnsError::Nsec { proof, .. })) => proofs.push(proof),
				Err(NetError::Dns(DnsError::DnssecBogus)) => proofs.push(Proof::Bogus),
				Err(_) => proofs.push(Proof::Insecure),
			}
		}
		summarize(proofs)
	}
}

impl Connector for MxConnector {
	fn connect(&self, domain: &str, policy: Option<&Policy>) -> ConnectFuture<'_> {
		self.connect_skipping(domain, policy, &[])
	}

	fn connect_skipping(
		&self,
		domain: &str,
		policy: Option<&Policy>,
		tried: &[String],
	) -> ConnectFuture<'_> {
		let domain = domain.to_string();
		let policy = policy.cloned();
		let tried = tried.to_vec();
		Box::pin(async move {
			let (hosts, mx) = self.exchangers(&domain).await?;
			let hosts = candidates(&domain, hosts, policy.as_ref(), &tried)?;
			let (host, stream) = first_reachable(&domain, &hosts, |host| {
				let host = host.to_string();
				async move {
					let addresses: Vec<std::net::SocketAddr> =
						tokio::net::lookup_host((host.as_str(), 25))
							.await?
							.collect();
					connect_any(&addresses, TcpStream::connect).await
				}
			})
			.await?;
			let local_ip = stream.local_addr().ok().map(|addr| addr.ip());
			let peer_ip = stream.peer_addr().ok().map(|addr| addr.ip());
			Ok(Connection {
				stream: Box::new(stream),
				host,
				local_ip,
				peer_ip,
				mx,
			})
		})
	}
}

/// The exchangers to try, in preference order: those `policy` permits
/// (never an unlisted host under MTA-STS enforce), at most
/// [`MAX_EXCHANGERS`] of them, and only those after the last one in `tried`,
/// which already turned this attempt away.
pub(crate) fn candidates(
	domain: &str,
	mut hosts: Vec<String>,
	policy: Option<&Policy>,
	tried: &[String],
) -> Result<Vec<String>, DeliveryError> {
	if let Some(policy) = policy {
		hosts.retain(|host| policy.permits_mx(host));
		if hosts.is_empty() {
			// Never contact unlisted hosts under enforce: retry later.
			return Err(DeliveryError::Transient(format!(
				"no MTA-STS-permitted MX for {domain}"
			)));
		}
	}
	hosts.truncate(MAX_EXCHANGERS);
	let after = hosts
		.iter()
		.rposition(|host| tried.contains(host))
		.map_or(0, |index| index + 1);
	let rest = hosts.split_off(after);
	if rest.is_empty() {
		return Err(DeliveryError::Transient(format!(
			"no further exchanger for {domain}"
		)));
	}
	Ok(rest)
}

/// Open a connection to the first of `addresses` (one exchanger's) that
/// answers, trying at most [`MAX_ADDRESSES`] of them, each for an equal
/// share of [`timeouts::CONNECT`]: the exchanger's whole connect stays
/// within that limit however many addresses it publishes, and one address
/// that never answers does not use up the time of the next.
pub(crate) async fn connect_any<S, F, Fut>(
	addresses: &[std::net::SocketAddr],
	mut open: F,
) -> std::io::Result<S>
where
	F: FnMut(std::net::SocketAddr) -> Fut,
	Fut: Future<Output = std::io::Result<S>>,
{
	let tried = addresses.len().clamp(1, MAX_ADDRESSES);
	let share = timeouts::CONNECT / u32::try_from(tried).unwrap_or(1);
	let mut last = std::io::Error::new(std::io::ErrorKind::NotFound, "no address to connect to");
	for address in addresses.iter().take(MAX_ADDRESSES) {
		last = match tokio::time::timeout(share, open(*address)).await {
			Ok(Ok(stream)) => return Ok(stream),
			Ok(Err(error)) => error,
			Err(_) => std::io::Error::new(
				std::io::ErrorKind::TimedOut,
				format!("{address} did not answer within {}s", share.as_secs()),
			),
		};
	}
	Err(last)
}

/// Open a connection to the first of `hosts` that answers, in order, giving
/// each [`timeouts::CONNECT`] before moving on to the next (RFC 5321
/// section 5.1). The error is the last host's.
pub(crate) async fn first_reachable<S, F, Fut>(
	domain: &str,
	hosts: &[String],
	mut open: F,
) -> Result<(String, S), DeliveryError>
where
	F: FnMut(&str) -> Fut,
	Fut: Future<Output = std::io::Result<S>>,
{
	let mut last_error = DeliveryError::Transient(format!("no exchangers for {domain}"));
	for host in hosts {
		last_error = match tokio::time::timeout(timeouts::CONNECT, open(host)).await {
			Ok(Ok(stream)) => return Ok((host.clone(), stream)),
			Ok(Err(error)) => {
				DeliveryError::Transient(format!("connect to {host}:25 failed: {error}"))
			}
			Err(_) => DeliveryError::Transient(format!(
				"connect to {host}:25 timed out after {}s",
				timeouts::CONNECT.as_secs()
			)),
		};
	}
	Err(last_error)
}

#[cfg(test)]
#[path = "resolver_tests.rs"]
mod tests;
