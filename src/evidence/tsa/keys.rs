//! The signature algorithms a token and its certificates may use, mapped
//! onto `ring`: RSA PKCS#1 v1.5 with SHA-256/384/512, ECDSA P-256 and P-384
//! with SHA-256/384, and Ed25519. Anything else is refused by name rather
//! than skipped.

use ring::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use x509_parser::prelude::X509Certificate;

use super::der::{Reader, parse_one, tag};
use super::oid;

pub(super) fn signed_by(certificate: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> bool {
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
pub(super) fn cms_algorithm(
	signature_algorithm: &[u8],
	digest_algorithm: &[u8],
	spki: &[u8],
) -> Result<&'static dyn VerificationAlgorithm, &'static str> {
	let hash = match signature_algorithm {
		a if a == oid::RSA || a == oid::EC_PUBLIC_KEY => digest_algorithm,
		other => return certificate_algorithm(other, spki),
	};
	let (kind, curve, _) = spki_parts(spki).ok_or("unreadable key")?;
	match kind {
		k if k == oid::RSA => rsa_for(hash),
		k if k == oid::EC_PUBLIC_KEY => ecdsa_for(curve, hash),
		_ => None,
	}
	.ok_or("unsupported signature algorithm")
}

/// The verification algorithm for a signature algorithm OID that names
/// its hash (`sha256WithRSAEncryption`, `ecdsa-with-SHA384`, Ed25519).
fn certificate_algorithm(
	algorithm: &[u8],
	spki: &[u8],
) -> Result<&'static dyn VerificationAlgorithm, &'static str> {
	let (_, curve, _) = spki_parts(spki).ok_or("unreadable key")?;
	match algorithm {
		a if a == oid::RSA_SHA256 => rsa_for(oid::SHA256),
		a if a == oid::RSA_SHA384 => rsa_for(oid::SHA384),
		a if a == oid::RSA_SHA512 => rsa_for(oid::SHA512),
		a if a == oid::ECDSA_SHA256 => ecdsa_for(curve, oid::SHA256),
		a if a == oid::ECDSA_SHA384 => ecdsa_for(curve, oid::SHA384),
		a if a == oid::ED25519 => Some(&signature::ED25519 as &dyn VerificationAlgorithm),
		_ => None,
	}
	.ok_or("unsupported signature algorithm")
}

pub(super) fn verify_with(
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
