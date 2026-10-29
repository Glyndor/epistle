//! DKIM private keys from another server, normalised to the form epistle
//! loads: PKCS#8 PEM, version 2 for ed25519 (with the public key, which
//! `ring` requires) and PKCS#8 for RSA.
//!
//! Mox writes ed25519 keys as PKCS#8 version 1 (Go's
//! `x509.MarshalPKCS8PrivateKey` leaves the public key out), and Stalwart's
//! RSA keys are often PKCS#1 (`BEGIN RSA PRIVATE KEY`). Both are rewritten
//! here; the key itself never changes, so the published DNS record still
//! matches. Key material only lives in [`Zeroizing`] buffers and never
//! reaches an error message.

use base64::Engine;
use ring::signature::{Ed25519KeyPair, KeyPair, RsaKeyPair};
use serde::Serialize;
use zeroize::Zeroizing;

/// The largest key file read. A 4096-bit RSA key in PEM is about 3.3 KiB.
pub(crate) const MAX_KEY_BYTES: usize = 64 * 1024;

/// A DKIM signing algorithm epistle can use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Algorithm {
	/// ed25519-sha256 (RFC 8463).
	Ed25519,
	/// rsa-sha256.
	Rsa,
}

/// The start of an ed25519 PKCS#8 version 1 key: SEQUENCE, version 0,
/// the Ed25519 algorithm identifier, and the 32-octet seed's wrapper.
const ED25519_V1_PREFIX: [u8; 16] = [
	0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// The PKCS#8 version 2 envelope `ring` writes for an ed25519 key, before
/// the seed; the public key follows after [`ED25519_V2_MIDDLE`].
const ED25519_V2_PREFIX: [u8; 16] = [
	0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const ED25519_V2_MIDDLE: [u8; 3] = [0x81, 0x21, 0x00];

/// The rsaEncryption algorithm identifier with its NULL parameters.
const RSA_ALGORITHM: [u8; 15] = [
	0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
];

/// A private key ready to be written, as PKCS#8 DER.
pub(crate) struct Normalized {
	/// The algorithm the key is for.
	pub(crate) algorithm: Algorithm,
	/// PKCS#8 DER.
	pub(crate) pkcs8: Zeroizing<Vec<u8>>,
}

/// Why a key cannot be used. None of these carry key material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum KeyError {
	/// No PEM block, or one that does not decode.
	#[error("not a PEM private key")]
	NotPem,
	/// A passphrase-protected key.
	#[error("the key is encrypted with a passphrase")]
	Encrypted,
	/// Neither an ed25519 nor a usable RSA key (RSA under 2048 bits included).
	#[error("not an ed25519 or RSA (2048 bits or more) private key")]
	Unsupported,
	/// The key is not the algorithm the source configuration says.
	#[error("the key does not match the configured algorithm")]
	WrongAlgorithm,
}

/// Decode a PEM private key and normalise it. `expected` is the algorithm
/// the source configuration names, if it names one.
pub(crate) fn normalize(pem: &str, expected: Option<Algorithm>) -> Result<Normalized, KeyError> {
	let (label, der) = pem_block(pem)?;
	let normalized = match label.as_str() {
		"PRIVATE KEY" => from_pkcs8(der)?,
		"RSA PRIVATE KEY" => rsa(wrap_pkcs1(&der))?,
		"ENCRYPTED PRIVATE KEY" => return Err(KeyError::Encrypted),
		_ => return Err(KeyError::Unsupported),
	};
	match expected {
		Some(algorithm) if algorithm != normalized.algorithm => Err(KeyError::WrongAlgorithm),
		_ => Ok(normalized),
	}
}

fn from_pkcs8(der: Zeroizing<Vec<u8>>) -> Result<Normalized, KeyError> {
	if Ed25519KeyPair::from_pkcs8(&der).is_ok() {
		return Ok(Normalized {
			algorithm: Algorithm::Ed25519,
			pkcs8: der,
		});
	}
	if der.len() == 48 && der[..16] == ED25519_V1_PREFIX {
		return ed25519_v2(&der[16..]);
	}
	rsa(der)
}

/// Build the version 2 form of an ed25519 key from its 32-octet seed.
fn ed25519_v2(seed: &[u8]) -> Result<Normalized, KeyError> {
	let pair = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| KeyError::Unsupported)?;
	let mut der = Zeroizing::new(Vec::with_capacity(83));
	der.extend_from_slice(&ED25519_V2_PREFIX);
	der.extend_from_slice(seed);
	der.extend_from_slice(&ED25519_V2_MIDDLE);
	der.extend_from_slice(pair.public_key().as_ref());
	Ed25519KeyPair::from_pkcs8(&der).map_err(|_| KeyError::Unsupported)?;
	Ok(Normalized {
		algorithm: Algorithm::Ed25519,
		pkcs8: der,
	})
}

fn rsa(der: Zeroizing<Vec<u8>>) -> Result<Normalized, KeyError> {
	RsaKeyPair::from_pkcs8(&der).map_err(|_| KeyError::Unsupported)?;
	Ok(Normalized {
		algorithm: Algorithm::Rsa,
		pkcs8: der,
	})
}

/// Wrap a PKCS#1 RSAPrivateKey in a PKCS#8 PrivateKeyInfo.
fn wrap_pkcs1(pkcs1: &[u8]) -> Zeroizing<Vec<u8>> {
	let mut body = Zeroizing::new(Vec::with_capacity(pkcs1.len() + 32));
	body.extend_from_slice(&[0x02, 0x01, 0x00]);
	body.extend_from_slice(&RSA_ALGORITHM);
	body.push(0x04);
	der_length(pkcs1.len(), &mut body);
	body.extend_from_slice(pkcs1);
	let mut out = Zeroizing::new(Vec::with_capacity(body.len() + 4));
	out.push(0x30);
	der_length(body.len(), &mut out);
	out.extend_from_slice(&body);
	out
}

/// Append a DER length.
fn der_length(length: usize, out: &mut Vec<u8>) {
	if length < 0x80 {
		out.push(length as u8);
		return;
	}
	let bytes = length.to_be_bytes();
	let skip = bytes.iter().take_while(|&&b| b == 0).count();
	out.push(0x80 | (bytes.len() - skip) as u8);
	out.extend_from_slice(&bytes[skip..]);
}

/// The label and decoded body of the first PEM block in `text`.
fn pem_block(text: &str) -> Result<(String, Zeroizing<Vec<u8>>), KeyError> {
	if text.len() > MAX_KEY_BYTES {
		return Err(KeyError::NotPem);
	}
	let start = text.find("-----BEGIN ").ok_or(KeyError::NotPem)?;
	let rest = &text[start + 11..];
	let label_end = rest.find("-----").ok_or(KeyError::NotPem)?;
	let label = rest[..label_end].to_string();
	let body_start = label_end + 5;
	let end_marker = format!("-----END {label}-----");
	let end = rest[body_start..]
		.find(&end_marker)
		.ok_or(KeyError::NotPem)?;
	let body = &rest[body_start..body_start + end];
	if body.contains("Proc-Type:") {
		return Err(KeyError::Encrypted);
	}
	let compact: Zeroizing<String> =
		Zeroizing::new(body.chars().filter(|c| !c.is_ascii_whitespace()).collect());
	let der = base64::engine::general_purpose::STANDARD
		.decode(compact.as_bytes())
		.map_err(|_| KeyError::NotPem)?;
	Ok((label, Zeroizing::new(der)))
}

/// PKCS#8 DER as a PEM file body.
pub(crate) fn to_pem(pkcs8: &[u8]) -> Zeroizing<String> {
	let body = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(pkcs8));
	let mut pem = Zeroizing::new(String::from("-----BEGIN PRIVATE KEY-----\n"));
	for chunk in body.as_bytes().chunks(64) {
		pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
		pem.push('\n');
	}
	pem.push_str("-----END PRIVATE KEY-----\n");
	pem
}

/// Whether `selector` is a DKIM selector that is also safe as a file name:
/// dot-separated labels of letters, digits and hyphens (RFC 6376 §3.1).
pub(crate) fn valid_selector(selector: &str) -> bool {
	!selector.is_empty()
		&& selector.len() <= 63
		&& selector.split('.').all(|label| {
			!label.is_empty()
				&& label
					.bytes()
					.all(|b| b.is_ascii_alphanumeric() || b == b'-')
		})
}

#[cfg(test)]
mod tests;
