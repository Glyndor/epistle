//! Connecting to the responsible server for a recipient domain.

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::mtasts::Policy;

use super::client::DeliveryError;

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
}

impl Connection {
	/// A connection over a transport without socket addresses.
	pub fn new(stream: BoxedStream, host: String) -> Self {
		Connection {
			stream,
			host,
			local_ip: None,
			peer_ip: None,
		}
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
	async fn exchangers(&self, domain: &str) -> Result<Vec<String>, DeliveryError> {
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
				records.sort_by_key(|mx| mx.preference);
				let records = records
					.iter()
					.map(|mx| (mx.preference, mx.exchange.to_utf8()))
					.collect();
				exchangers_from(domain, records)
			}
			// No MX records: fall back to the implicit MX.
			Err(NetError::Dns(DnsError::NoRecordsFound(_))) => Ok(vec![domain.to_string()]),
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

impl Connector for MxConnector {
	fn connect(&self, domain: &str, policy: Option<&Policy>) -> ConnectFuture<'_> {
		let domain = domain.to_string();
		let policy = policy.cloned();
		Box::pin(async move {
			let mut hosts = self.exchangers(&domain).await?;
			if let Some(policy) = &policy {
				hosts.retain(|host| policy.permits_mx(host));
				if hosts.is_empty() {
					// Never contact unlisted hosts under enforce: retry later.
					return Err(DeliveryError::Transient(format!(
						"no MTA-STS-permitted MX for {domain}"
					)));
				}
			}
			let mut last_error = DeliveryError::Transient(format!("no exchangers for {domain}"));
			for host in hosts {
				match TcpStream::connect((host.as_str(), 25)).await {
					Ok(stream) => {
						let local_ip = stream.local_addr().ok().map(|addr| addr.ip());
						let peer_ip = stream.peer_addr().ok().map(|addr| addr.ip());
						return Ok(Connection {
							stream: Box::new(stream),
							host,
							local_ip,
							peer_ip,
						});
					}
					Err(error) => {
						last_error = DeliveryError::Transient(format!(
							"connect to {host}:25 failed: {error}"
						));
					}
				}
			}
			Err(last_error)
		})
	}
}

#[cfg(test)]
#[path = "resolver_tests.rs"]
mod tests;
