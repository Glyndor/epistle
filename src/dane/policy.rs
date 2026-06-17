//! DANE authentication policy for TLS peers (RFC 7671 §5, RFC 7672 §2.2).
//!
//! Given the TLSA records published for a service and the certificate chain it
//! presented, decide whether any record authenticates the peer. End-entity
//! usages (DANE-EE/PKIX-EE) match the leaf certificate; trust-anchor usages
//! (DANE-TA/PKIX-TA) match any certificate in the presented chain. PKIX-based
//! usages additionally require ordinary PKIX validation, which the TLS stack
//! performs; this layer only checks the TLSA association.

use super::tlsa::{CertUsage, TlsaRecord};

/// A presented certificate: its full DER and its SubjectPublicKeyInfo DER.
pub struct CertView<'a> {
	pub der: &'a [u8],
	pub spki: &'a [u8],
}

impl<'a> CertView<'a> {
	/// Convenience constructor.
	pub fn new(der: &'a [u8], spki: &'a [u8]) -> Self {
		CertView { der, spki }
	}
}

/// Whether any TLSA record authenticates the presented chain.
///
/// `leaf` is the server certificate; `chain` are the remaining certificates it
/// presented (intermediates and root) used for trust-anchor assertions. With no
/// records, DANE does not apply and this returns `false`.
pub fn authenticate(records: &[TlsaRecord], leaf: &CertView, chain: &[CertView]) -> bool {
	records.iter().any(|record| match record.usage {
		// End-entity: the leaf certificate itself must match.
		CertUsage::DaneEe | CertUsage::PkixEe => record.matches_cert(leaf.der, leaf.spki),
		// Trust anchor: some certificate in the presented chain must match.
		CertUsage::DaneTa | CertUsage::PkixTa => std::iter::once(leaf)
			.chain(chain)
			.any(|cert| record.matches_cert(cert.der, cert.spki)),
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use ring::digest;

	const LEAF: &[u8] = b"--leaf cert der--";
	const LEAF_SPKI: &[u8] = b"--leaf spki--";
	const CA: &[u8] = b"--ca cert der--";
	const CA_SPKI: &[u8] = b"--ca spki--";

	fn sha256(data: &[u8]) -> Vec<u8> {
		digest::digest(&digest::SHA256, data).as_ref().to_vec()
	}

	fn leaf() -> CertView<'static> {
		CertView::new(LEAF, LEAF_SPKI)
	}

	fn chain() -> Vec<CertView<'static>> {
		vec![CertView::new(CA, CA_SPKI)]
	}

	#[test]
	fn dane_ee_matches_leaf() {
		let record = TlsaRecord::from_parts(3, 1, 1, sha256(LEAF_SPKI)).expect("record");
		assert!(authenticate(&[record], &leaf(), &chain()));
	}

	#[test]
	fn dane_ee_rejects_other_leaf() {
		let record = TlsaRecord::from_parts(3, 1, 1, sha256(b"someone else")).expect("record");
		assert!(!authenticate(&[record], &leaf(), &chain()));
	}

	#[test]
	fn dane_ta_matches_chain_certificate() {
		let record = TlsaRecord::from_parts(2, 0, 1, sha256(CA)).expect("record");
		assert!(authenticate(&[record], &leaf(), &chain()));
	}

	#[test]
	fn dane_ta_does_not_match_unrelated_ca() {
		let record = TlsaRecord::from_parts(2, 0, 1, sha256(b"other ca")).expect("record");
		assert!(!authenticate(&[record], &leaf(), &chain()));
	}

	#[test]
	fn any_matching_record_authenticates() {
		let bad = TlsaRecord::from_parts(3, 1, 1, sha256(b"no")).expect("record");
		let good = TlsaRecord::from_parts(3, 1, 1, sha256(LEAF_SPKI)).expect("record");
		assert!(authenticate(&[bad, good], &leaf(), &chain()));
	}

	#[test]
	fn no_records_means_not_authenticated() {
		assert!(!authenticate(&[], &leaf(), &chain()));
	}
}
