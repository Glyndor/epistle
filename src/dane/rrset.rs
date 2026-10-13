//! What a DNSSEC-validating TLSA lookup means for delivery (RFC 7672
//! sections 2.1 and 2.2): no DANE, DANE with records to authenticate
//! against, or a secure RRset none of whose records can be used.

use super::tlsa::{CertUsage, TlsaRecord};
use crate::spf::DnsFailure;

/// The TLSA RRset of one MX host, classified for delivery.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TlsaRrset {
	/// No secure TLSA RRset: the name does not exist, has no TLSA records,
	/// or its zone is not signed. DANE does not apply.
	#[default]
	Absent,
	/// A secure RRset with at least one usable record. Unusable records in
	/// the same RRset are left out.
	Usable(Vec<TlsaRecord>),
	/// A secure RRset in which no record is usable. DANE cannot
	/// authenticate the server, but TLS stays mandatory.
	Unusable,
}

impl TlsaRrset {
	/// The records to authenticate the server against; empty unless usable.
	pub fn records(&self) -> &[TlsaRecord] {
		match self {
			TlsaRrset::Usable(records) => records,
			TlsaRrset::Absent | TlsaRrset::Unusable => &[],
		}
	}
}

/// The DNSSEC status of an answer, as the validating resolver reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validation {
	/// Chained to a trust anchor.
	Secure,
	/// Provably unsigned.
	Insecure,
	/// Signed, but the signatures do not validate.
	Bogus,
	/// No trust anchor covers the name.
	Indeterminate,
}

/// One TLSA answer: its validation status and its RDATA fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsaAnswer {
	/// DNSSEC status of the RRset the answer came in.
	pub validation: Validation,
	/// Certificate usage field.
	pub usage: u8,
	/// Selector field.
	pub selector: u8,
	/// Matching type field.
	pub matching_type: u8,
	/// Certificate association data.
	pub data: Vec<u8>,
}

/// Classify the answers of one TLSA query.
///
/// A bogus answer is a lookup failure: delivery waits rather than treating
/// a forged or broken signature as "no DANE" (RFC 7672 section 2.1.1).
/// Unvalidated answers never count. Of a secure RRset only DANE-TA and
/// DANE-EE records with a known selector and matching type are usable;
/// PKIX-TA and PKIX-EE are not (RFC 7672 section 3.1.3). A secure RRset
/// with none usable is `Unusable`, which still forbids cleartext (RFC 7672
/// section 2.2).
pub fn classify(answers: &[TlsaAnswer]) -> Result<TlsaRrset, DnsFailure> {
	if answers
		.iter()
		.any(|answer| answer.validation == Validation::Bogus)
	{
		return Err(DnsFailure::Temporary);
	}
	let secure: Vec<&TlsaAnswer> = answers
		.iter()
		.filter(|answer| answer.validation == Validation::Secure)
		.collect();
	if secure.is_empty() {
		return Ok(TlsaRrset::Absent);
	}
	let usable: Vec<TlsaRecord> = secure
		.into_iter()
		.filter_map(|answer| {
			TlsaRecord::from_parts(
				answer.usage,
				answer.selector,
				answer.matching_type,
				answer.data.clone(),
			)
		})
		.filter(|record| matches!(record.usage, CertUsage::DaneTa | CertUsage::DaneEe))
		.collect();
	if usable.is_empty() {
		Ok(TlsaRrset::Unusable)
	} else {
		Ok(TlsaRrset::Usable(usable))
	}
}

#[cfg(test)]
#[path = "rrset_tests.rs"]
mod tests;
