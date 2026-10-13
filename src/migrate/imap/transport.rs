//! The transport under the IMAP client: where to connect, how the
//! connection is protected, and the TLS handshake with its certificate
//! check.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use super::client::ClientError;
use super::wire::{Limits, WireError};

/// How the connection is protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Security {
	/// TLS from the first octet (port 993).
	Tls,
	/// Plaintext greeting, then STARTTLS before anything else (port 143).
	StartTls,
	/// No encryption at all. Only reachable through an explicit opt-in.
	Plaintext,
}

/// How the server certificate is checked.
#[derive(Debug, Clone)]
pub(crate) enum Verify {
	/// Against the public web PKI roots plus `extra` trust anchors.
	Roots {
		/// Extra trust anchors (a private CA, a self-signed server).
		extra: Vec<CertificateDer<'static>>,
	},
	/// Not at all: the connection is encrypted but not authenticated.
	Skip,
}

/// Where and how to connect.
#[derive(Debug, Clone)]
pub(crate) struct Endpoint {
	/// The server name: what is dialled and what the certificate must name.
	pub(crate) host: String,
	/// The TCP port.
	pub(crate) port: u16,
	/// Dial this address instead of resolving `host` (the certificate is
	/// still checked against `host`).
	pub(crate) address: Option<SocketAddr>,
	/// Transport protection.
	pub(crate) security: Security,
	/// Certificate checking.
	pub(crate) verify: Verify,
}

/// The duplex stream under the client: TCP, maybe wrapped in TLS.
pub(super) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// The first address `host` resolves to.
pub(super) async fn resolve(
	host: &str,
	port: u16,
	limits: Limits,
) -> Result<SocketAddr, ClientError> {
	let mut addresses = tokio::time::timeout(limits.idle, tokio::net::lookup_host((host, port)))
		.await
		.map_err(|_| WireError::Timeout)?
		.map_err(WireError::Io)?;
	addresses
		.next()
		.ok_or_else(|| ClientError::Protocol(format!("{host} does not resolve")))
}

/// A TLS session over `stream`, checking the certificate as `endpoint`
/// says.
pub(super) async fn handshake(
	stream: Box<dyn Io>,
	endpoint: &Endpoint,
	limits: Limits,
) -> Result<tokio_rustls::client::TlsStream<Box<dyn Io>>, ClientError> {
	crate::tls::ensure_crypto_provider();
	let config = match &endpoint.verify {
		Verify::Roots { extra } => {
			let mut roots = RootCertStore::empty();
			roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
			for anchor in extra {
				roots
					.add(anchor.clone())
					.map_err(|error| ClientError::Tls(error.to_string()))?;
			}
			ClientConfig::builder()
				.with_root_certificates(roots)
				.with_no_client_auth()
		}
		Verify::Skip => ClientConfig::builder()
			.dangerous()
			.with_custom_certificate_verifier(Arc::new(super::insecure::AnyCertificate::new()))
			.with_no_client_auth(),
	};
	let name = ServerName::try_from(endpoint.host.clone())
		.map_err(|_| ClientError::Tls(format!("{} is not a valid TLS name", endpoint.host)))?;
	tokio::time::timeout(
		limits.idle,
		tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, stream),
	)
	.await
	.map_err(|_| WireError::Timeout)?
	.map_err(|error| ClientError::Tls(error.to_string()))
}
