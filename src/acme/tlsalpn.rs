//! TLS-ALPN-01 challenge (RFC 8737).
//!
//! The CA opens a TLS connection to the domain on port 443 negotiating the
//! `acme-tls/1` ALPN protocol and expects a self-signed certificate carrying the
//! `id-pe-acmeIdentifier` extension whose value is the SHA-256 of the
//! challenge's key authorization. We build that certificate and serve it through
//! a [`ResolvesServerCert`] that only answers `acme-tls/1` handshakes, so the
//! normal certificate is used for ordinary traffic.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;

/// The ALPN protocol identifier for the TLS-ALPN-01 challenge (RFC 8737 §4).
pub const ACME_TLS_ALPN_PROTOCOL: &[u8] = b"acme-tls/1";

/// `id-pe-acmeIdentifier` (1.3.6.1.5.5.7.1.31).
const ACME_IDENTIFIER_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 31];

/// Errors building a challenge certificate.
#[derive(Debug, thiserror::Error)]
#[error("tls-alpn-01: {0}")]
pub struct ChallengeError(String);

/// Build the self-signed challenge certificate for `domain` carrying the
/// SHA-256 of `key_authorization` in a critical `acmeIdentifier` extension.
pub fn challenge_certificate(
	domain: &str,
	key_authorization: &str,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), ChallengeError> {
	let digest = ring::digest::digest(&ring::digest::SHA256, key_authorization.as_bytes());
	// The extension value is a DER OCTET STRING wrapping the 32-byte digest.
	let mut content = vec![0x04, 0x20];
	content.extend_from_slice(digest.as_ref());
	let mut extension = rcgen::CustomExtension::from_oid_content(ACME_IDENTIFIER_OID, content);
	extension.set_criticality(true);

	let mut params = rcgen::CertificateParams::new(vec![domain.to_string()])
		.map_err(|error| ChallengeError(error.to_string()))?;
	params.custom_extensions.push(extension);
	let key = rcgen::KeyPair::generate().map_err(|error| ChallengeError(error.to_string()))?;
	let cert = params
		.self_signed(&key)
		.map_err(|error| ChallengeError(error.to_string()))?;
	let key_der = PrivateKeyDer::try_from(key.serialize_der())
		.map_err(|error| ChallengeError(error.to_string()))?;
	Ok((cert.der().clone(), key_der))
}

/// Assemble a rustls [`CertifiedKey`] from a certificate and its key.
fn certified_key(
	cert: CertificateDer<'static>,
	key: PrivateKeyDer<'static>,
) -> Result<Arc<CertifiedKey>, ChallengeError> {
	let signing = tokio_rustls::rustls::crypto::ring::default_provider()
		.key_provider
		.load_private_key(key)
		.map_err(|error| ChallengeError(error.to_string()))?;
	Ok(Arc::new(CertifiedKey::new(vec![cert], signing)))
}

/// Challenge certificates keyed by the domain under validation.
#[derive(Default)]
pub struct AlpnChallengeStore {
	inner: RwLock<HashMap<String, Arc<CertifiedKey>>>,
}

impl AlpnChallengeStore {
	/// An empty store.
	pub fn new() -> Self {
		AlpnChallengeStore::default()
	}

	/// Generate and register the challenge certificate for `domain`.
	pub fn set(&self, domain: &str, key_authorization: &str) -> Result<(), ChallengeError> {
		let (cert, key) = challenge_certificate(domain, key_authorization)?;
		let certified = certified_key(cert, key)?;
		self.inner
			.write()
			.expect("alpn store")
			.insert(domain.to_ascii_lowercase(), certified);
		Ok(())
	}

	/// Drop a domain's challenge certificate once validation is done.
	pub fn remove(&self, domain: &str) {
		self.inner
			.write()
			.expect("alpn store")
			.remove(&domain.to_ascii_lowercase());
	}

	/// The challenge certificate for `domain`, if registered.
	fn get(&self, domain: &str) -> Option<Arc<CertifiedKey>> {
		self.inner
			.read()
			.expect("alpn store")
			.get(&domain.to_ascii_lowercase())
			.cloned()
	}
}

/// A certificate resolver that answers `acme-tls/1` handshakes with the
/// challenge certificate for the requested SNI host, and every other handshake
/// with the normal `fallback` certificate.
#[derive(Debug)]
pub struct AlpnResolver {
	store: Arc<AlpnChallengeStore>,
	fallback: Arc<CertifiedKey>,
}

impl AlpnResolver {
	/// Wrap a challenge store and the normal server certificate.
	pub fn new(store: Arc<AlpnChallengeStore>, fallback: Arc<CertifiedKey>) -> Self {
		AlpnResolver { store, fallback }
	}
}

impl std::fmt::Debug for AlpnChallengeStore {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("AlpnChallengeStore")
	}
}

impl ResolvesServerCert for AlpnResolver {
	fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
		let is_acme = client_hello
			.alpn()
			.is_some_and(|mut protocols| protocols.any(|p| p == ACME_TLS_ALPN_PROTOCOL));
		if is_acme {
			// A challenge handshake must name the domain and have a cert ready;
			// otherwise there is nothing valid to serve (fail closed).
			return client_hello
				.server_name()
				.and_then(|sni| self.store.get(sni));
		}
		Some(Arc::clone(&self.fallback))
	}
}

#[cfg(test)]
#[path = "tlsalpn_tests.rs"]
mod tests;
