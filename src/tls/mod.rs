//! TLS material loading: PEM files into a rustls acceptor.

pub(crate) mod https;

use std::path::Path;
use std::sync::Arc;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{ServerConfig, SupportedProtocolVersion, version};

use crate::config::Tls;

/// The protocol versions a listener negotiates, newest first. `epistle limits
/// show` reads the oldest one from here, so the minimum it reports is the one
/// every acceptor is built with.
pub(crate) const PROTOCOL_VERSIONS: &[&SupportedProtocolVersion] =
	&[&version::TLS13, &version::TLS12];

/// Install the ring `CryptoProvider` as the process default.
///
/// Some dependencies (`sqlx`, `reqwest`, ...) pull rustls with the
/// aws-lc-rs provider enabled too; with two providers compiled in,
/// rustls cannot pick one automatically and its config builders
/// panic. Installing ring explicitly makes the choice deterministic
/// across the whole process. We skip silently when another provider
/// is already installed because the `crypto_provider()` method reads
/// the running default, not what we just installed.
pub fn ensure_crypto_provider() {
	if tokio_rustls::rustls::crypto::CryptoProvider::get_default().is_none() {
		let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
	}
}

/// Errors while loading TLS material. Always fatal: the server refuses to
/// start with broken TLS rather than degrade to plaintext.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
	/// The PEM file could not be read from disk: missing file, permission
	/// denied, or another I/O failure. Carries the path string and the
	/// underlying `std::io::Error`.
	#[error("cannot read {path}: {source}")]
	Read {
		/// Path that was attempted, formatted with `Display`.
		path: String,
		/// Underlying I/O error returned by `std::fs`.
		source: std::io::Error,
	},
	/// The PEM file was readable but contained no `CERTIFICATE` blocks.
	/// Carries the path string.
	#[error("no certificates found in {0}")]
	NoCertificates(String),
	/// The PEM file was readable but contained no private key block.
	/// Carries the path string.
	#[error("no private key found in {0}")]
	NoPrivateKey(String),
	/// rustls rejected the certificate/key pair: the key does not match
	/// the certificate, or the material is otherwise unusable. Carries the
	/// underlying message.
	#[error("invalid TLS material: {0}")]
	Invalid(String),
}

/// Build a TLS acceptor from the configured PEM files. With `client_ca` set the
/// acceptor requests and verifies client certificates (for SASL EXTERNAL),
/// still allowing clients that present none (they fall back to password auth).
pub fn acceptor(config: &Tls) -> Result<TlsAcceptor, TlsError> {
	ensure_crypto_provider();
	let certs = load_certs(&config.cert_file)?;
	let key = load_key(&config.key_file)?;
	let server_config = server_config(certs, key, config.client_ca.as_deref())?;
	Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Assemble a `ServerConfig`, enabling client-certificate verification against
/// `client_ca` when one is configured.
fn server_config(
	certs: Vec<CertificateDer<'static>>,
	key: PrivateKeyDer<'static>,
	client_ca: Option<&Path>,
) -> Result<ServerConfig, TlsError> {
	let builder = ServerConfig::builder();
	let with_auth = match client_ca {
		Some(ca) => builder.with_client_cert_verifier(client_verifier(ca)?),
		None => builder.with_no_client_auth(),
	};
	with_auth
		.with_single_cert(certs, key)
		.map_err(|error| TlsError::Invalid(error.to_string()))
}

/// A client-certificate verifier trusting `ca_file`. Unauthenticated clients
/// are still allowed (no certificate), so password auth keeps working; a client
/// that *does* present a certificate must chain to the configured trust anchor.
fn client_verifier(
	ca_file: &Path,
) -> Result<Arc<dyn tokio_rustls::rustls::server::danger::ClientCertVerifier>, TlsError> {
	use tokio_rustls::rustls::RootCertStore;
	use tokio_rustls::rustls::server::WebPkiClientVerifier;

	let mut roots = RootCertStore::empty();
	for cert in load_certs(ca_file)? {
		roots
			.add(cert)
			.map_err(|error| TlsError::Invalid(error.to_string()))?;
	}
	WebPkiClientVerifier::builder(Arc::new(roots))
		.allow_unauthenticated()
		.build()
		.map_err(|error| TlsError::Invalid(error.to_string()))
}

/// The authenticated identity in a verified client certificate: its first
/// `rfc822Name` (email) Subject Alternative Name. Returns `None` when the
/// certificate cannot be parsed or carries no email SAN. The certificate has
/// already been verified against the trust anchor by rustls before this runs.
pub fn identity_from_cert(der: &[u8]) -> Option<String> {
	use x509_parser::extensions::GeneralName;
	use x509_parser::prelude::FromDer;

	let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der).ok()?;
	let san = cert.subject_alternative_name().ok()??;
	san.value.general_names.iter().find_map(|name| match name {
		GeneralName::RFC822Name(email) => Some((*email).to_string()),
		_ => None,
	})
}

/// The `tls-server-end-point` channel binding (RFC 5929) for
/// SCRAM-SHA-256-PLUS: the SHA-256 of the server's leaf certificate (DER).
/// Returns `None` if the certificate cannot be read.
///
/// SHA-256 is used unconditionally; a certificate signed with a different hash
/// is not supported for channel binding (clients fall back to plain SCRAM).
pub fn tls_server_end_point(config: &Tls) -> Option<Vec<u8>> {
	let certs = load_certs(&config.cert_file).ok()?;
	let leaf = certs.first()?;
	let digest = ring::digest::digest(&ring::digest::SHA256, leaf.as_ref());
	Some(digest.as_ref().to_vec())
}

/// The DER bytes of the leaf certificate in `path`, the same bytes the running
/// `serve` would present on the wire (the apply phase points the `[tls]`
/// section at this file: `keys/cert.pem` for a static configuration,
/// `<data_dir>/acme/cert.pem` once ACME renewal takes over). The probe uses
/// this to pin the verifier: only a server that presents these exact bytes
/// passes, which catches the case where the file on disk has been renewed
/// but the listener has not reloaded.
pub fn leaf_cert_der(path: &Path) -> Result<Vec<u8>, TlsError> {
	let certs = load_certs(path)?;
	let leaf = certs
		.into_iter()
		.next()
		.ok_or_else(|| TlsError::NoCertificates(path.display().to_string()))?;
	Ok(leaf.as_ref().to_vec())
}

/// Build an acceptor from an in-memory PEM chain and key (e.g. ACME-issued).
pub fn acceptor_from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<TlsAcceptor, TlsError> {
	ensure_crypto_provider();
	let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
		.collect::<Result<_, _>>()
		.map_err(|error| TlsError::Invalid(error.to_string()))?;
	if certs.is_empty() {
		return Err(TlsError::NoCertificates("<memory>".into()));
	}
	let key = PrivateKeyDer::from_pem_slice(key_pem)
		.map_err(|error| TlsError::Invalid(error.to_string()))?;
	let server_config = ServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(certs, key)
		.map_err(|error| TlsError::Invalid(error.to_string()))?;
	Ok(TlsAcceptor::from(Arc::new(server_config)))
}

mod reload;
pub use reload::ReloadableAcceptor;

/// How long a client gets to complete a TLS handshake, on an implicit-TLS
/// listener or after STARTTLS. Every read after the handshake has its own
/// protocol timeout; without this one a client that connects and stalls
/// mid-handshake would hold the connection and its task forever.
pub const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Accept a TLS connection on `stream`, giving up with
/// [`std::io::ErrorKind::TimedOut`] after [`HANDSHAKE_TIMEOUT`].
pub async fn accept_within<IO>(
	acceptor: &TlsAcceptor,
	stream: IO,
) -> std::io::Result<tokio_rustls::server::TlsStream<IO>>
where
	IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
	accept_until(
		acceptor,
		stream,
		tokio::time::Instant::now() + HANDSHAKE_TIMEOUT,
	)
	.await
}

/// [`accept_within`], but never past `deadline`: a caller with a deadline of
/// its own for the whole phase does not get [`HANDSHAKE_TIMEOUT`] on top of it.
pub async fn accept_until<IO>(
	acceptor: &TlsAcceptor,
	stream: IO,
	deadline: tokio::time::Instant,
) -> std::io::Result<tokio_rustls::server::TlsStream<IO>>
where
	IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
	let deadline = deadline.min(tokio::time::Instant::now() + HANDSHAKE_TIMEOUT);
	match tokio::time::timeout_at(deadline, acceptor.accept(stream)).await {
		Ok(result) => result,
		Err(_) => Err(std::io::Error::new(
			std::io::ErrorKind::TimedOut,
			"TLS handshake timed out",
		)),
	}
}

mod served;
pub use served::{CertSource, ServedTls, served_tls};

mod end_point;
pub use end_point::{EndPoint, end_point_of};

pub mod watch;

pub mod watch_tlsa;

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
	let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
		.map_err(|source| TlsError::Read {
			path: path.display().to_string(),
			source: std::io::Error::other(source),
		})?
		.collect::<Result<_, _>>()
		.map_err(|error| TlsError::Invalid(error.to_string()))?;
	if certs.is_empty() {
		return Err(TlsError::NoCertificates(path.display().to_string()));
	}
	Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
	PrivateKeyDer::from_pem_file(path).map_err(|error| match error {
		rustls_pki_types::pem::Error::NoItemsFound => {
			TlsError::NoPrivateKey(path.display().to_string())
		}
		rustls_pki_types::pem::Error::Io(source) => TlsError::Read {
			path: path.display().to_string(),
			source,
		},
		other => TlsError::Invalid(other.to_string()),
	})
}

#[cfg(test)]
mod tests;

/// Test-only helpers shared across modules.
#[cfg(test)]
pub(crate) mod test_support {
	use tokio_rustls::TlsAcceptor;
	use tokio_rustls::rustls::ServerConfig;
	use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

	/// Build an acceptor from a fresh self-signed certificate, returning the
	/// certificate so test clients can trust it.
	pub(crate) fn acceptor_and_cert() -> (TlsAcceptor, CertificateDer<'static>) {
		let certified = rcgen::generate_simple_self_signed(vec!["mail.example.org".to_string()])
			.expect("generate certificate");
		let cert = certified.cert.der().clone();
		let key = PrivateKeyDer::try_from(certified.signing_key.serialize_der()).expect("key der");
		super::ensure_crypto_provider();
		let config = ServerConfig::builder()
			.with_no_client_auth()
			.with_single_cert(vec![cert.clone()], key)
			.expect("server config");
		(TlsAcceptor::from(std::sync::Arc::new(config)), cert)
	}
}
