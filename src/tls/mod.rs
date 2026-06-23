//! TLS material loading: PEM files into a rustls acceptor.

use std::path::Path;
use std::sync::{Arc, RwLock};

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;

use crate::config::Tls;

/// Install the ring `CryptoProvider` as the process default, once.
///
/// Some dependencies (sqlx, reqwest) pull rustls with the aws-lc-rs provider
/// enabled too; with two providers compiled in, rustls cannot pick one
/// automatically and its config builders panic. Installing ring explicitly
/// makes the choice deterministic across the whole process.
pub fn ensure_crypto_provider() {
	use std::sync::Once;
	static INIT: Once = Once::new();
	INIT.call_once(|| {
		let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
	});
}

/// Errors while loading TLS material. Always fatal: the server refuses to
/// start with broken TLS rather than degrade to plaintext.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
	#[error("cannot read {path}: {source}")]
	Read {
		path: String,
		source: std::io::Error,
	},
	#[error("no certificates found in {0}")]
	NoCertificates(String),
	#[error("no private key found in {0}")]
	NoPrivateKey(String),
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

/// A hot-swappable TLS acceptor. Certificate renewal replaces the active
/// acceptor without dropping the listener, so new handshakes use the fresh
/// certificate while in-flight connections finish on the old one.
#[derive(Clone)]
pub struct ReloadableAcceptor {
	inner: Arc<RwLock<TlsAcceptor>>,
}

impl ReloadableAcceptor {
	/// Wrap an initial acceptor.
	pub fn new(acceptor: TlsAcceptor) -> Self {
		ReloadableAcceptor {
			inner: Arc::new(RwLock::new(acceptor)),
		}
	}

	/// The current acceptor (cheap clone; shares config via `Arc`).
	pub fn current(&self) -> TlsAcceptor {
		self.inner.read().expect("tls acceptor lock").clone()
	}

	/// Swap in a newly issued acceptor.
	pub fn reload(&self, acceptor: TlsAcceptor) {
		*self.inner.write().expect("tls acceptor lock") = acceptor;
	}
}

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

#[cfg(test)]
mod tests {
	use super::*;
	use std::path::PathBuf;

	fn self_signed_pem(domain: &str) -> (String, String) {
		let c = rcgen::generate_simple_self_signed(vec![domain.to_string()]).expect("cert");
		(c.cert.pem(), c.signing_key.serialize_pem())
	}

	#[test]
	fn acceptor_from_pem_builds_and_reloads() {
		let (cert1, key1) = self_signed_pem("a.example");
		let a1 = acceptor_from_pem(cert1.as_bytes(), key1.as_bytes()).expect("acceptor 1");
		let handle = ReloadableAcceptor::new(a1);
		let _ = handle.current(); // smoke: current acceptor available

		let (cert2, key2) = self_signed_pem("b.example");
		let a2 = acceptor_from_pem(cert2.as_bytes(), key2.as_bytes()).expect("acceptor 2");
		handle.reload(a2);
		let _ = handle.current(); // smoke: still available after reload
	}

	#[test]
	fn acceptor_from_pem_rejects_missing_material() {
		assert!(acceptor_from_pem(b"", b"").is_err());
	}

	#[test]
	fn identity_from_cert_reads_email_san() {
		let mut params = rcgen::CertificateParams::new(vec![]).expect("params");
		params.subject_alt_names.push(rcgen::SanType::Rfc822Name(
			"alice@example.org".try_into().expect("ia5"),
		));
		let key = rcgen::KeyPair::generate().expect("key");
		let cert = params.self_signed(&key).expect("self-signed");
		assert_eq!(
			identity_from_cert(cert.der().as_ref()),
			Some("alice@example.org".to_string())
		);
	}

	#[test]
	fn identity_from_cert_none_without_email_san() {
		// A DNS-only certificate carries no rfc822Name SAN.
		let certified =
			rcgen::generate_simple_self_signed(vec!["mail.example.org".to_string()]).expect("cert");
		assert_eq!(identity_from_cert(certified.cert.der().as_ref()), None);
	}

	#[test]
	fn identity_from_cert_rejects_garbage() {
		assert_eq!(identity_from_cert(b"not a certificate"), None);
	}

	/// Write a self-signed certificate + key pair into `dir`.
	pub(crate) fn write_self_signed(dir: &Path) -> (PathBuf, PathBuf) {
		let certified = rcgen::generate_simple_self_signed(vec!["mail.example.org".to_string()])
			.expect("generate certificate");
		let cert_path = dir.join("cert.pem");
		let key_path = dir.join("key.pem");
		std::fs::write(&cert_path, certified.cert.pem()).expect("write cert");
		std::fs::write(&key_path, certified.signing_key.serialize_pem()).expect("write key");
		(cert_path, key_path)
	}

	fn tls_config(cert_file: PathBuf, key_file: PathBuf) -> Tls {
		let toml = format!(
			"cert_file = \"{}\"\nkey_file = \"{}\"\n",
			cert_file.display(),
			key_file.display()
		);
		toml::from_str(&toml).expect("tls config")
	}

	#[test]
	fn builds_acceptor_from_valid_material() {
		let dir = tempfile::tempdir().expect("tempdir");
		let (cert, key) = write_self_signed(dir.path());
		assert!(acceptor(&tls_config(cert, key)).is_ok());
	}

	#[test]
	fn fails_on_missing_cert_file() {
		let dir = tempfile::tempdir().expect("tempdir");
		let (_, key) = write_self_signed(dir.path());
		let result = acceptor(&tls_config(dir.path().join("missing.pem"), key));
		assert!(matches!(result, Err(TlsError::Read { .. })));
	}

	#[test]
	fn fails_on_missing_key_file() {
		let dir = tempfile::tempdir().expect("tempdir");
		let (cert, _) = write_self_signed(dir.path());
		let result = acceptor(&tls_config(cert, dir.path().join("missing.pem")));
		assert!(matches!(result, Err(TlsError::Read { .. })));
	}

	#[test]
	fn fails_on_empty_cert_file() {
		let dir = tempfile::tempdir().expect("tempdir");
		let (_, key) = write_self_signed(dir.path());
		let empty = dir.path().join("empty.pem");
		std::fs::write(&empty, b"").expect("write empty");
		let result = acceptor(&tls_config(empty, key));
		assert!(matches!(result, Err(TlsError::NoCertificates(_))));
	}

	#[test]
	fn fails_on_key_without_key_material() {
		let dir = tempfile::tempdir().expect("tempdir");
		let (cert, _) = write_self_signed(dir.path());
		let bogus = dir.path().join("bogus.pem");
		std::fs::write(&bogus, b"not a key").expect("write bogus");
		let result = acceptor(&tls_config(cert, bogus));
		assert!(matches!(result, Err(TlsError::NoPrivateKey(_))));
	}

	#[test]
	fn fails_on_mismatched_cert_and_key() {
		let dir = tempfile::tempdir().expect("tempdir");
		let (cert, _) = write_self_signed(dir.path());
		let other = tempfile::tempdir().expect("tempdir");
		let (_, foreign_key) = write_self_signed(other.path());
		// A key from a different certificate must be rejected.
		let result = acceptor(&tls_config(cert, foreign_key));
		assert!(matches!(result, Err(TlsError::Invalid(_))));
	}
}
