//! Certificate helpers shared by the DANE layers.

/// The SubjectPublicKeyInfo (DER) of an X.509 certificate, or `None` if the
/// certificate cannot be parsed.
pub fn spki_of(cert_der: &[u8]) -> Option<Vec<u8>> {
	use x509_parser::prelude::FromDer;
	let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der).ok()?;
	Some(cert.tbs_certificate.subject_pki.raw.to_vec())
}
