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
	/// Full DER encoding of the certificate (the same bytes the TLS stack
	/// received on the wire). Used by `selector = 0` TLSA associations
	/// (full-certificate match).
	pub der: &'a [u8],
	/// DER encoding of the certificate's `SubjectPublicKeyInfo` (SPKI).
	/// Used by `selector = 1` TLSA associations (subject-public-key match).
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

/// The result of applying a DANE policy to a presented chain (RFC 7672 §2.2).
///
/// `Mismatch` is the fail-closed case: TLSA records were published (and
/// DNSSEC-validated) but none matched the certificate, so the peer is NOT
/// authenticated and delivery must not proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaneOutcome {
	/// At least one DNSSEC-validated TLSA record matched the chain.
	Authenticated,
	/// No (validated) TLSA records exist: DANE does not apply, proceed
	/// opportunistically.
	NoRecords,
	/// TLSA records exist but none matched: authentication failed.
	Mismatch,
}

/// Decide the DANE outcome for a presented chain against published records.
///
/// The records passed here MUST already be DNSSEC-validated (RFC 7672 §2.1):
/// unvalidated TLSA is never trusted and must be presented as an empty slice so
/// this returns [`DaneOutcome::NoRecords`]. With records present, the peer is
/// authenticated only when one matches; otherwise the outcome is
/// [`DaneOutcome::Mismatch`] and the caller must refuse delivery (fail closed).
pub fn dane_outcome(records: &[TlsaRecord], leaf: &CertView, chain: &[CertView]) -> DaneOutcome {
	if records.is_empty() {
		DaneOutcome::NoRecords
	} else if authenticate(records, leaf, chain) {
		DaneOutcome::Authenticated
	} else {
		DaneOutcome::Mismatch
	}
}

#[cfg(test)]
mod tests;
