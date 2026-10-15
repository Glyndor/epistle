//! Verifying a timestamp token against a digest and pinned trust anchors.
//!
//! A token is accepted only when every one of these holds:
//!
//! 1. it stamps exactly our SHA-256 digest (and our nonce, when we sent one);
//! 2. the signed `messageDigest` is the digest of the TSTInfo as carried;
//! 3. the signer's certificate is in the token, is the one the signed
//!    `signingCertificate` attribute names, carries the critical
//!    `timeStamping` extended key usage, and was valid at the stamped time;
//! 4. the signature over the signed attributes verifies with that key;
//! 5. a chain of certificates from the token, each signed by the next and
//!    valid at the stamped time, reaches a key whose SubjectPublicKeyInfo
//!    hashes to a pinned anchor.
//!
//! Anchors are pinned by key, not by certificate, so a root that is both
//! self-signed and cross-signed (as Sectigo's is) matches either way.

use ring::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use x509_parser::prelude::{FromDer, X509Certificate};

use super::der::{Reader, parse_one, tag};
use super::oid;
use super::token::{SignerId, Token, TokenError, parse_response};
use crate::evidence::record::{sha256, to_hex};

/// The longest chain walked from the signer to an anchor.
const MAX_CHAIN: usize = 6;

/// What a verified token says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamp {
	/// When the TSA stamped the digest, epoch seconds.
	pub gen_time: u64,
	/// The token's serial number, hex.
	pub serial: String,
	/// Hex SHA-256 of the anchor key the chain reached.
	pub anchor: String,
}

/// Why a token does not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
	/// The response is not a token.
	Token(TokenError),
	/// The token stamps something else.
	Imprint,
	/// The token carries another nonce.
	Nonce,
	/// A check of the token's signature or certificates failed.
	Untrusted(&'static str),
}

impl From<TokenError> for VerifyError {
	fn from(error: TokenError) -> Self {
		VerifyError::Token(error)
	}
}

impl std::fmt::Display for VerifyError {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			VerifyError::Token(error) => write!(formatter, "{error}"),
			VerifyError::Imprint => formatter.write_str("the token stamps a different digest"),
			VerifyError::Nonce => formatter.write_str("the token carries a different nonce"),
			VerifyError::Untrusted(why) => write!(formatter, "the token does not verify: {why}"),
		}
	}
}

/// Verify the TimeStampResp `response` for `digest`, trusting the keys
/// whose SPKI SHA-256 is in `anchors`. `nonce` is checked when given.
pub fn verify(
	response: &[u8],
	digest: &[u8; 32],
	nonce: Option<u64>,
	anchors: &[[u8; 32]],
) -> Result<Stamp, VerifyError> {
	let token = parse_response(response)?;
	if token.tst.hash_algorithm != oid::SHA256 || token.tst.hashed_message != digest {
		return Err(VerifyError::Imprint);
	}
	if let Some(nonce) = nonce {
		let expected = super::der::unsigned_content(nonce);
		if token.tst.nonce != Some(expected.as_slice()) {
			return Err(VerifyError::Nonce);
		}
	}
	let when = i64::try_from(token.tst.gen_time).unwrap_or(i64::MAX);
	let digest_of = |algorithm: &[u8], bytes: &[u8]| -> Option<Vec<u8>> {
		let algorithm = match algorithm {
			a if a == oid::SHA256 => &ring::digest::SHA256,
			a if a == oid::SHA384 => &ring::digest::SHA384,
			a if a == oid::SHA512 => &ring::digest::SHA512,
			a if a == oid::SHA1 => &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
			_ => return None,
		};
		Some(ring::digest::digest(algorithm, bytes).as_ref().to_vec())
	};
	let content_digest = digest_of(token.signer.digest_algorithm, token.tst_der)
		.ok_or(VerifyError::Untrusted("unsupported digest algorithm"))?;
	if content_digest != token.signer.message_digest {
		return Err(VerifyError::Untrusted(
			"messageDigest does not match the TSTInfo",
		));
	}
	let certificates = parse_certificates(&token)?;
	let signer = find_signer(&token, &certificates)?;
	let (hash_algorithm, hash) = token.signer.certificate_hash;
	if digest_of(hash_algorithm, signer.as_raw()).as_deref() != Some(hash) {
		return Err(VerifyError::Untrusted(
			"signingCertificate does not name the signer",
		));
	}
	check_timestamping(signer, when)?;
	let mut signed = token.signer.signed_attributes.to_vec();
	signed[0] = tag::SET;
	let algorithm = cms_algorithm(
		token.signer.signature_algorithm,
		token.signer.digest_algorithm,
		signer.public_key().raw,
	)?;
	if !verify_with(
		algorithm,
		signer.public_key().raw,
		&signed,
		token.signer.signature,
	) {
		return Err(VerifyError::Untrusted("bad signature"));
	}
	let anchor = chain_to_anchor(signer, &certificates, anchors, when)?;
	Ok(Stamp {
		gen_time: token.tst.gen_time,
		serial: to_hex(token.tst.serial),
		anchor: to_hex(&anchor),
	})
}

fn parse_certificates<'a>(token: &Token<'a>) -> Result<Vec<X509Certificate<'a>>, VerifyError> {
	token
		.certificates
		.iter()
		.map(|der| {
			X509Certificate::from_der(der)
				.map(|(_, certificate)| certificate)
				.map_err(|_| VerifyError::Untrusted("a certificate does not parse"))
		})
		.collect()
}

fn find_signer<'b, 'a>(
	token: &Token<'a>,
	certificates: &'b [X509Certificate<'a>],
) -> Result<&'b X509Certificate<'a>, VerifyError> {
	certificates
		.iter()
		.find(|certificate| match token.signer.id {
			SignerId::IssuerSerial(issuer, serial) => {
				certificate.issuer().as_raw() == issuer && certificate.raw_serial() == serial
			}
			SignerId::KeyId(id) => key_identifier(certificate) == Some(id),
		})
		.ok_or(VerifyError::Untrusted(
			"the signer's certificate is not in the token",
		))
}

fn key_identifier<'a>(certificate: &X509Certificate<'a>) -> Option<&'a [u8]> {
	use x509_parser::extensions::ParsedExtension;
	certificate
		.extensions()
		.iter()
		.find_map(|extension| match &extension.parsed_extension() {
			ParsedExtension::SubjectKeyIdentifier(id) => Some(id.0),
			_ => None,
		})
}

/// The signer must be a time-stamping key (RFC 3161 section 2.3) valid at
/// the stamped time.
fn check_timestamping(signer: &X509Certificate<'_>, when: i64) -> Result<(), VerifyError> {
	let usage = signer
		.extended_key_usage()
		.map_err(|_| VerifyError::Untrusted("unreadable extended key usage"))?
		.ok_or(VerifyError::Untrusted(
			"the signer has no extended key usage",
		))?;
	if !usage.critical || !usage.value.time_stamping {
		return Err(VerifyError::Untrusted(
			"the signer is not a critical timeStamping key",
		));
	}
	valid_at(signer, when)
}

fn valid_at(certificate: &X509Certificate<'_>, when: i64) -> Result<(), VerifyError> {
	let validity = certificate.validity();
	if when < validity.not_before.timestamp() || when > validity.not_after.timestamp() {
		return Err(VerifyError::Untrusted(
			"a certificate was not valid at the stamped time",
		));
	}
	Ok(())
}

/// Walk issuers from `signer` until a pinned key; return that key's hash.
fn chain_to_anchor(
	signer: &X509Certificate<'_>,
	certificates: &[X509Certificate<'_>],
	anchors: &[[u8; 32]],
	when: i64,
) -> Result<[u8; 32], VerifyError> {
	let mut current = signer;
	for _ in 0..MAX_CHAIN {
		let key = sha256(current.public_key().raw);
		if anchors.contains(&key) {
			return Ok(key);
		}
		let issuer = certificates
			.iter()
			.filter(|candidate| candidate.subject().as_raw() == current.issuer().as_raw())
			.find(|candidate| signed_by(current, candidate))
			.ok_or(VerifyError::Untrusted(
				"the chain does not reach a pinned anchor",
			))?;
		valid_at(issuer, when)?;
		if issuer.as_raw() == current.as_raw() {
			// Self-signed and not pinned: nothing further up.
			break;
		}
		current = issuer;
	}
	Err(VerifyError::Untrusted(
		"the chain does not reach a pinned anchor",
	))
}

fn signed_by(certificate: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> bool {
	let algorithm = certificate.signature_algorithm.algorithm.as_bytes();
	let Ok(verification) = certificate_algorithm(algorithm, issuer.public_key().raw) else {
		return false;
	};
	verify_with(
		verification,
		issuer.public_key().raw,
		certificate.tbs_certificate.as_ref(),
		&certificate.signature_value.data,
	)
}

/// The key inside an SPKI and its algorithm (and curve).
fn spki_parts(spki: &[u8]) -> Option<(&[u8], Option<&[u8]>, &[u8])> {
	let outer = parse_one(spki, tag::SEQUENCE).ok()?;
	let mut fields = outer.reader();
	let algorithm = fields.expect(tag::SEQUENCE).ok()?;
	let key = fields.expect(tag::BIT_STRING).ok()?;
	let mut parts = Reader::new(algorithm.value);
	let kind = parts.expect(tag::OID).ok()?.value;
	let curve = parts.optional(tag::OID).ok()?.map(|curve| curve.value);
	// The BIT STRING's first octet counts unused bits: zero for a key.
	let (unused, key) = key.value.split_first()?;
	(*unused == 0).then_some((kind, curve, key))
}

fn ecdsa_for(curve: Option<&[u8]>, hash: &[u8]) -> Option<&'static dyn VerificationAlgorithm> {
	Some(match (curve?, hash) {
		(c, h) if c == oid::P256 && h == oid::SHA256 => &signature::ECDSA_P256_SHA256_ASN1,
		(c, h) if c == oid::P256 && h == oid::SHA384 => &signature::ECDSA_P256_SHA384_ASN1,
		(c, h) if c == oid::P384 && h == oid::SHA256 => &signature::ECDSA_P384_SHA256_ASN1,
		(c, h) if c == oid::P384 && h == oid::SHA384 => &signature::ECDSA_P384_SHA384_ASN1,
		_ => return None,
	})
}

fn rsa_for(hash: &[u8]) -> Option<&'static dyn VerificationAlgorithm> {
	Some(match hash {
		h if h == oid::SHA256 => &signature::RSA_PKCS1_2048_8192_SHA256,
		h if h == oid::SHA384 => &signature::RSA_PKCS1_2048_8192_SHA384,
		h if h == oid::SHA512 => &signature::RSA_PKCS1_2048_8192_SHA512,
		_ => return None,
	})
}

/// The verification algorithm for a CMS signer: the signature algorithm
/// may name the key type only (`rsaEncryption`), with the hash in the
/// digest algorithm.
fn cms_algorithm(
	signature_algorithm: &[u8],
	digest_algorithm: &[u8],
	spki: &[u8],
) -> Result<&'static dyn VerificationAlgorithm, VerifyError> {
	let hash = match signature_algorithm {
		a if a == oid::RSA || a == oid::EC_PUBLIC_KEY => digest_algorithm,
		other => return certificate_algorithm(other, spki),
	};
	let (kind, curve, _) = spki_parts(spki).ok_or(VerifyError::Untrusted("unreadable key"))?;
	match kind {
		k if k == oid::RSA => rsa_for(hash),
		k if k == oid::EC_PUBLIC_KEY => ecdsa_for(curve, hash),
		_ => None,
	}
	.ok_or(VerifyError::Untrusted("unsupported signature algorithm"))
}

/// The verification algorithm for a signature algorithm OID that names
/// its hash (`sha256WithRSAEncryption`, `ecdsa-with-SHA384`, Ed25519).
fn certificate_algorithm(
	algorithm: &[u8],
	spki: &[u8],
) -> Result<&'static dyn VerificationAlgorithm, VerifyError> {
	let (_, curve, _) = spki_parts(spki).ok_or(VerifyError::Untrusted("unreadable key"))?;
	match algorithm {
		a if a == oid::RSA_SHA256 => rsa_for(oid::SHA256),
		a if a == oid::RSA_SHA384 => rsa_for(oid::SHA384),
		a if a == oid::RSA_SHA512 => rsa_for(oid::SHA512),
		a if a == oid::ECDSA_SHA256 => ecdsa_for(curve, oid::SHA256),
		a if a == oid::ECDSA_SHA384 => ecdsa_for(curve, oid::SHA384),
		a if a == oid::ED25519 => Some(&signature::ED25519 as &dyn VerificationAlgorithm),
		_ => None,
	}
	.ok_or(VerifyError::Untrusted("unsupported signature algorithm"))
}

fn verify_with(
	algorithm: &'static dyn VerificationAlgorithm,
	spki: &[u8],
	message: &[u8],
	signature: &[u8],
) -> bool {
	let Some((_, _, key)) = spki_parts(spki) else {
		return false;
	};
	UnparsedPublicKey::new(algorithm, key)
		.verify(message, signature)
		.is_ok()
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod tests;
