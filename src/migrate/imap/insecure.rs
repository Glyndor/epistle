//! The certificate verifier behind `--insecure-skip-verify`.
//!
//! It accepts any certificate chain for any name, so the connection is
//! encrypted but the server is not authenticated: anyone on the path can
//! read the password. The handshake signatures are still checked against
//! the presented certificate's own key, so the peer must at least hold the
//! key for the certificate it shows. The CLI prints a warning every time
//! this is used.

use std::sync::Arc;

use tokio_rustls::rustls::client::danger::{
	HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{DigitallySignedStruct, Error, SignatureScheme};

/// Accepts every certificate; see the module documentation.
#[derive(Debug)]
pub(crate) struct AnyCertificate {
	provider: Arc<CryptoProvider>,
}

impl AnyCertificate {
	/// A verifier using the process crypto provider's algorithms.
	pub(crate) fn new() -> Self {
		let provider = CryptoProvider::get_default()
			.cloned()
			.unwrap_or_else(|| Arc::new(tokio_rustls::rustls::crypto::ring::default_provider()));
		AnyCertificate { provider }
	}
}

impl ServerCertVerifier for AnyCertificate {
	fn verify_server_cert(
		&self,
		_end_entity: &CertificateDer<'_>,
		_intermediates: &[CertificateDer<'_>],
		_server_name: &ServerName<'_>,
		_ocsp_response: &[u8],
		_now: UnixTime,
	) -> Result<ServerCertVerified, Error> {
		Ok(ServerCertVerified::assertion())
	}

	fn verify_tls12_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, Error> {
		tokio_rustls::rustls::crypto::verify_tls12_signature(
			message,
			cert,
			dss,
			&self.provider.signature_verification_algorithms,
		)
	}

	fn verify_tls13_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, Error> {
		tokio_rustls::rustls::crypto::verify_tls13_signature(
			message,
			cert,
			dss,
			&self.provider.signature_verification_algorithms,
		)
	}

	fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
		self.provider
			.signature_verification_algorithms
			.supported_schemes()
	}
}
