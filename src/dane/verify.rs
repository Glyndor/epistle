//! Applying a DANE policy to a TLS peer's presented certificate chain.
//!
//! Bridges the raw DER certificates a rustls connection exposes to the
//! association-matching policy in [`super::policy`]: it extracts each
//! certificate's SubjectPublicKeyInfo (needed for selector `1` records) and runs
//! [`dane_outcome`](super::policy::dane_outcome). Fail-closed: a chain that
//! cannot be parsed against present records is a mismatch, never a pass.

use super::policy::{CertView, DaneOutcome, dane_outcome};
use super::tlsa::TlsaRecord;

/// The SubjectPublicKeyInfo (DER) of an X.509 certificate, or `None` if the
/// certificate cannot be parsed.
pub fn spki_of(cert_der: &[u8]) -> Option<Vec<u8>> {
	use x509_parser::prelude::FromDer;
	let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der).ok()?;
	Some(cert.tbs_certificate.subject_pki.raw.to_vec())
}

/// Apply the DANE policy to a peer's presented chain.
///
/// `chain_der` is the certificate chain exactly as the peer presented it: the
/// first entry is the leaf, the rest are intermediates/root. `records` MUST be
/// DNSSEC-validated TLSA records (an empty slice means "no validated records",
/// i.e. opportunistic). Returns the [`DaneOutcome`]; with records present but an
/// empty or unparseable chain the result is [`DaneOutcome::Mismatch`] (fail
/// closed).
pub fn verify_chain(records: &[TlsaRecord], chain_der: &[Vec<u8>]) -> DaneOutcome {
	if records.is_empty() {
		return DaneOutcome::NoRecords;
	}
	// Records are present: the peer MUST present a chain we can match. An empty
	// or unparseable chain cannot be authenticated.
	let spkis: Vec<Vec<u8>> = chain_der
		.iter()
		.map(|der| spki_of(der).unwrap_or_default())
		.collect();
	let views: Vec<CertView<'_>> = chain_der
		.iter()
		.zip(&spkis)
		.map(|(der, spki)| CertView::new(der, spki))
		.collect();
	let Some((leaf, rest)) = views.split_first() else {
		return DaneOutcome::Mismatch;
	};
	dane_outcome(records, leaf, rest)
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod tests;
