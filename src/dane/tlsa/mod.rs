//! TLSA records and certificate-association matching (RFC 6698, RFC 7671).
//!
//! A TLSA record asserts which certificate or public key is expected for a
//! service. This module parses records and answers the core question: does a
//! presented certificate (or its public key) match a record's association
//! data, given the record's selector and matching type. Chain/usage policy for
//! SMTP (RFC 7672) is layered on top.

use ring::digest;

/// Certificate usage (RFC 6698 §2.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertUsage {
	/// `0` PKIX-TA: CA constraint, chains to PKIX trust.
	PkixTa,
	/// `1` PKIX-EE: service certificate constraint, chains to PKIX trust.
	PkixEe,
	/// `2` DANE-TA: trust anchor assertion, own trust anchor.
	DaneTa,
	/// `3` DANE-EE: domain-issued certificate, matched directly.
	DaneEe,
}

/// Which part of the certificate the association covers (RFC 6698 §2.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selector {
	/// `0` the full certificate (DER).
	FullCert,
	/// `1` the SubjectPublicKeyInfo (DER).
	Spki,
}

/// How the association data is derived (RFC 6698 §2.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchingType {
	/// `0` exact match on the selected data.
	Full,
	/// `1` SHA-256 of the selected data.
	Sha256,
	/// `2` SHA-512 of the selected data.
	Sha512,
}

/// A parsed TLSA resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsaRecord {
	/// Certificate usage (the first field of the TLSA RDATA).
	pub usage: CertUsage,
	/// Which part of the certificate the association covers (the second
	/// field of the TLSA RDATA).
	pub selector: Selector,
	/// How the association data is derived (the third field of the TLSA
	/// RDATA).
	pub matching_type: MatchingType,
	/// The certificate association data (raw or hashed per `matching_type`).
	pub association: Vec<u8>,
}

impl TlsaRecord {
	/// Build from numeric fields and association bytes, rejecting unknown codes.
	pub fn from_parts(
		usage: u8,
		selector: u8,
		matching_type: u8,
		association: Vec<u8>,
	) -> Option<Self> {
		let usage = match usage {
			0 => CertUsage::PkixTa,
			1 => CertUsage::PkixEe,
			2 => CertUsage::DaneTa,
			3 => CertUsage::DaneEe,
			_ => return None,
		};
		let selector = match selector {
			0 => Selector::FullCert,
			1 => Selector::Spki,
			_ => return None,
		};
		let matching_type = match matching_type {
			0 => MatchingType::Full,
			1 => MatchingType::Sha256,
			2 => MatchingType::Sha512,
			_ => return None,
		};
		if association.is_empty() {
			return None;
		}
		Some(TlsaRecord {
			usage,
			selector,
			matching_type,
			association,
		})
	}

	/// Parse the presentation form `usage selector matching-type hexdata`.
	pub fn parse_presentation(text: &str) -> Option<Self> {
		let mut fields = text.split_whitespace();
		let usage = fields.next()?.parse().ok()?;
		let selector = fields.next()?.parse().ok()?;
		let matching_type = fields.next()?.parse().ok()?;
		// The hex data may be split across whitespace-separated groups.
		let hex: String = fields.collect();
		if hex.is_empty() {
			return None;
		}
		let association = decode_hex(&hex)?;
		Self::from_parts(usage, selector, matching_type, association)
	}

	/// Whether a presented certificate matches this record's association data.
	/// `cert_der` is the full certificate; `spki_der` its SubjectPublicKeyInfo.
	pub fn matches_cert(&self, cert_der: &[u8], spki_der: &[u8]) -> bool {
		let selected = match self.selector {
			Selector::FullCert => cert_der,
			Selector::Spki => spki_der,
		};
		let computed = match self.matching_type {
			MatchingType::Full => selected.to_vec(),
			MatchingType::Sha256 => digest::digest(&digest::SHA256, selected).as_ref().to_vec(),
			MatchingType::Sha512 => digest::digest(&digest::SHA512, selected).as_ref().to_vec(),
		};
		// Constant-time-ish: lengths differ for the wrong matching type, and the
		// comparison is over fixed-size digests in the common case.
		computed == self.association
	}
}

/// Decode a hex string (even length, ASCII hex digits) into bytes.
fn decode_hex(hex: &str) -> Option<Vec<u8>> {
	if !hex.len().is_multiple_of(2) {
		return None;
	}
	let mut bytes = Vec::with_capacity(hex.len() / 2);
	let raw = hex.as_bytes();
	for pair in raw.as_chunks::<2>().0 {
		let hi = (pair[0] as char).to_digit(16)?;
		let lo = (pair[1] as char).to_digit(16)?;
		bytes.push((hi * 16 + lo) as u8);
	}
	Some(bytes)
}

#[cfg(test)]
mod tests;
