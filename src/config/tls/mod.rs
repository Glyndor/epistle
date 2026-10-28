//! TLS configuration: certificate and key locations.

use std::path::PathBuf;

use serde::Deserialize;

/// TLS material for all listeners. PEM-encoded files.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
	/// Certificate chain, leaf first (PEM).
	pub cert_file: PathBuf,
	/// Private key for the leaf certificate (PEM, PKCS#8 or RSA/EC).
	pub key_file: PathBuf,
	/// Trust anchor (PEM) for verifying TLS client certificates. When set,
	/// clients may authenticate with a certificate (SASL EXTERNAL); the
	/// account is taken from the certificate's verified email (SAN). Absent
	/// disables client-certificate authentication.
	#[serde(default)]
	pub client_ca: Option<PathBuf>,
}

#[cfg(test)]
mod tests;
