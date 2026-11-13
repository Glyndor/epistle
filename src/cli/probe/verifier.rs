//! The certificate verifiers the probe uses: the pinned one and the
//! unverified fallback.

use super::*;

/// Certificate verifier for the probe that accepts only the certificate
/// the operator has on disk under `[tls] cert_file`. The cert bytes
/// are the same the apply phase chose: `keys/cert.pem` for a static
/// config, `<data_dir>/acme/cert.pem` once ACME takes over; either way
/// the file the listener binds with is the one TOML points at. When
/// the listener has not reloaded after a renewal, the bytes on the
/// wire no longer match the file on disk and the probe fails with a
/// line that names the path.
///
/// The handshake signatures are still verified for real, against the
/// presented certificate's own key, using the ring provider's
/// algorithms: the pin only authenticates *which* certificate may
/// appear, not the proof the peer holds the matching private key.
pub(crate) struct PinnedCertVerifier {
	/// DER of the leaf certificate in `[tls] cert_file`. The verifier
	/// accepts only a presented certificate whose bytes match exactly.
	expected_der: Vec<u8>,
	/// The path the operator has on disk. Carried so the failure line
	/// can name the file the operator should compare against.
	cert_path: PathBuf,
	/// Crypto provider whose signature algorithms verify the
	/// handshake signatures against the presented certificate.
	provider: Arc<rustls::crypto::CryptoProvider>,
}

impl std::fmt::Debug for PinnedCertVerifier {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("PinnedCertVerifier")
			.field("cert_path", &self.cert_path)
			.finish()
	}
}

impl PinnedCertVerifier {
	/// Build the verifier from `path`. Returns `Err` when the file
	/// cannot be read or has no certificates; the `Display` message
	/// is what the probe prints on the failed listener line.
	pub(crate) fn from_path(path: &Path) -> std::io::Result<Self> {
		let expected_der = crate::tls::leaf_cert_der(path)
			.map_err(|error| std::io::Error::other(format!("{error}")))?;
		Ok(Self {
			expected_der,
			cert_path: path.to_path_buf(),
			provider: default_provider(),
		})
	}
}

pub(super) fn default_provider() -> Arc<rustls::crypto::CryptoProvider> {
	rustls::crypto::CryptoProvider::get_default()
		.cloned()
		.unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()))
}

impl ServerCertVerifier for PinnedCertVerifier {
	fn verify_server_cert(
		&self,
		end_entity: &CertificateDer<'_>,
		_intermediates: &[CertificateDer<'_>],
		_server_name: &ServerName<'_>,
		_ocsp_response: &[u8],
		_now: UnixTime,
	) -> Result<ServerCertVerified, Error> {
		if end_entity.as_ref() != self.expected_der.as_slice() {
			return Err(Error::General(format!(
				"certificate presented differs from {} (not reloaded after renewal?)",
				self.cert_path.display()
			)));
		}
		Ok(ServerCertVerified::assertion())
	}

	fn verify_tls12_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, Error> {
		rustls::crypto::verify_tls12_signature(
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
		rustls::crypto::verify_tls13_signature(
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

/// Outcome of trying to build a [`PinnedCertVerifier`] for the run.
/// `None` means the config has no `[tls]` section (TLS listeners under
/// such a config fail the probe with a clear reason); `Some(Ok(_))`
/// means the verifier is ready; `Some(Err(_))` carries the loader's
/// message so each TLS listener surfaces it verbatim.
pub(super) fn build_verifier(
	tls_cert_path: Option<&Path>,
) -> Option<Result<Arc<dyn ServerCertVerifier>, String>> {
	let path = tls_cert_path?;
	ensure_crypto_provider();
	Some(
		PinnedCertVerifier::from_path(path)
			.map(|v| Arc::new(v) as Arc<dyn ServerCertVerifier>)
			.map_err(|error| error.to_string()),
	)
}

/// Pull the verifier for a TLS handshake, or return the fail-line
/// reason when no verifier is available.
pub(super) fn require_verifier(
	pinned: &Option<Result<Arc<dyn ServerCertVerifier>, String>>,
) -> Result<Arc<dyn ServerCertVerifier>, String> {
	match pinned {
		None => Err(
			"no [tls] cert_file configured but a TLS listener listens on the probe address"
				.to_string(),
		),
		Some(Err(error)) => Err(error.clone()),
		Some(Ok(verifier)) => Ok(verifier.clone()),
	}
}
