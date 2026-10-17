//! How the TLS part of one outbound delivery attempt ended, in the result
//! types TLS-RPT reports use (RFC 8460 §4.3).
//!
//! The SMTP client fills this in as it goes; the worker turns it into a
//! TLS-RPT session for the recipient domain. An attempt that never reached
//! the STARTTLS decision (connection refused, bad greeting) has no outcome.

use tokio_rustls::rustls::{CertificateError, Error as TlsError};

/// The TLS outcome of one delivery attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsOutcome {
	/// The handshake completed and the certificate was authenticated as the
	/// attempt required (PKIX, DANE, or none in opportunistic mode).
	Success,
	/// The RFC 8460 §4.3 result type of the failure.
	Failure(&'static str),
}

/// The remote offered no STARTTLS, or refused the command.
pub const STARTTLS_NOT_SUPPORTED: &str = "starttls-not-supported";
/// No TLSA record matched the presented certificate.
pub const TLSA_INVALID: &str = "tlsa-invalid";
/// The recipient domain publishes an MTA-STS policy but the HTTPS fetch
/// of that policy failed (RFC 8460 §4.3, RFC 8461 §3.3).
pub const STS_POLICY_FETCH_ERROR: &str = "sts-policy-fetch-error";
/// The recipient domain's MTA-STS policy could not be parsed.
pub const STS_POLICY_INVALID: &str = "sts-policy-invalid";
const CERTIFICATE_EXPIRED: &str = "certificate-expired";
const CERTIFICATE_HOST_MISMATCH: &str = "certificate-host-mismatch";
const CERTIFICATE_NOT_TRUSTED: &str = "certificate-not-trusted";
/// The handshake failed for a reason that is not about the certificate,
/// such as a server that stopped answering mid-handshake.
pub const VALIDATION_FAILURE: &str = "validation-failure";

/// Classify a failed STARTTLS handshake. The certificate checks rustls ran
/// map onto their RFC 8460 names; anything else in the handshake is the
/// catch-all `validation-failure`.
pub fn classify_handshake(error: &std::io::Error) -> &'static str {
	let Some(TlsError::InvalidCertificate(certificate)) = error
		.get_ref()
		.and_then(|inner| inner.downcast_ref::<TlsError>())
	else {
		return VALIDATION_FAILURE;
	};
	match certificate {
		CertificateError::Expired | CertificateError::ExpiredContext { .. } => CERTIFICATE_EXPIRED,
		CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
			CERTIFICATE_HOST_MISMATCH
		}
		_ => CERTIFICATE_NOT_TRUSTED,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn wrapped(error: TlsError) -> std::io::Error {
		std::io::Error::new(std::io::ErrorKind::InvalidData, error)
	}

	#[test]
	fn certificate_errors_map_to_rfc8460_result_types() {
		let cases = [
			(CertificateError::Expired, CERTIFICATE_EXPIRED),
			(CertificateError::NotValidForName, CERTIFICATE_HOST_MISMATCH),
			(CertificateError::UnknownIssuer, CERTIFICATE_NOT_TRUSTED),
			(CertificateError::BadSignature, CERTIFICATE_NOT_TRUSTED),
		];
		for (certificate, expected) in cases {
			assert_eq!(
				classify_handshake(&wrapped(TlsError::InvalidCertificate(certificate))),
				expected
			);
		}
		assert_eq!(
			classify_handshake(&wrapped(TlsError::HandshakeNotComplete)),
			VALIDATION_FAILURE
		);
		assert_eq!(
			classify_handshake(&std::io::Error::other("reset")),
			VALIDATION_FAILURE
		);
	}
}
