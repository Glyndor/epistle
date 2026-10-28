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
