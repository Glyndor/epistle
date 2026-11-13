//! DKIM signing (RFC 6376 section 5) for outbound mail.
//!
//! Signing is in two halves: [`block`] reads the message into the header
//! block a signature covers, and [`holder`] holds the key and signs that
//! block. [`Signer::sign`] runs both in one call.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, RSA_PKCS1_SHA256, RsaKeyPair};

use super::canon;
use super::signature::Canon;

pub(super) mod block;
pub(super) mod holder;
mod wire;

pub use block::{HeaderBlock, Malformed};
pub use holder::{KeyHolder, Refusal};

/// Headers included in the signature when present.
const SIGNED_HEADERS: &[&str] = &[
	"from",
	"to",
	"cc",
	"subject",
	"date",
	"message-id",
	"reply-to",
	"sender",
	"mime-version",
	"content-type",
	"content-transfer-encoding",
	"references",
	"in-reply-to",
	"list-id",
	"list-unsubscribe",
	"list-unsubscribe-post",
	"list-help",
	"list-post",
	"list-owner",
	"list-archive",
	"feedback-id",
	"disposition-notification-to",
	"return-receipt-to",
	"auto-submitted",
	"organization",
	"x-epistle",
];

/// List each name once beyond its present count, even when absent (RFC 6376 section 5.4).
const OVERSIGNED_HEADERS: &[&str] = &[
	"from",
	"to",
	"cc",
	"subject",
	"reply-to",
	"date",
	"message-id",
	"list-unsubscribe",
	"list-unsubscribe-post",
	"content-type",
	"disposition-notification-to",
	"return-receipt-to",
	// The server writes this one; a client that adds a second copy of it
	// has to keep both, or the signature breaks. Nothing in the path
	// legitimately writes `Auto-Submitted`, so oversigning it costs
	// nothing at delivery and stops a forged "this was automatic" claim.
	"auto-submitted",
];

/// A DKIM signer: always ed25519, optionally also RSA for dual-signing.
pub struct Signer {
	selector: String,
	key: Ed25519KeyPair,
	rsa: Option<Arc<RsaSigner>>,
}

/// An additional RSA-SHA256 signing key with its own selector.
struct RsaSigner {
	selector: String,
	key: RsaKeyPair,
}

/// Why signing material could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
	/// The PEM key file could not be read from disk: missing file, permission
	/// denied, or another I/O failure. Carries the path string and the
	/// underlying `std::io::Error`.
	#[error("cannot read key file {path}: {source}")]
	Read {
		/// Path that was attempted, formatted with `Display`.
		path: String,
		/// Underlying I/O error returned by `std::fs`.
		source: std::io::Error,
	},
	/// The PEM file was read but its body is not a valid ed25519 PKCS#8 key
	/// (or the file is not PEM at all). Carries the path string for the
	/// error message.
	#[error("invalid ed25519 key in {0}: expected PKCS#8 PEM")]
	InvalidKey(String),
}

impl Signer {
	/// Load a PKCS#8 PEM ed25519 private key.
	pub fn load(selector: &str, key_file: &std::path::Path) -> Result<Self, SignerError> {
		Ok(Signer {
			selector: selector.to_string(),
			key: load_ed25519_key(key_file)?,
			rsa: None,
		})
	}

	/// Add an RSA-SHA256 signature with its own selector and PKCS#8 PEM key, so
	/// the message carries both ed25519 and RSA DKIM signatures (RFC 8463).
	pub fn with_rsa(
		mut self,
		selector: &str,
		key_file: &std::path::Path,
	) -> Result<Self, SignerError> {
		self.rsa = Some(Arc::new(RsaSigner {
			selector: selector.to_string(),
			key: load_rsa_key(key_file)?,
		}));
		Ok(self)
	}

	/// Replace the ed25519 signing material and, when `rsa` names a
	/// selector and key file, the RSA key too. Without `rsa` the loaded RSA
	/// key (if any) is retained. Nothing is replaced unless every new key
	/// loads.
	pub(crate) fn with_rotated_keys(
		&self,
		selector: &str,
		key_file: &std::path::Path,
		rsa: Option<(&str, &std::path::Path)>,
	) -> Result<Self, SignerError> {
		let signer = Self::load(selector, key_file)?;
		match rsa {
			Some((rsa_selector, rsa_key_file)) => signer.with_rsa(rsa_selector, rsa_key_file),
			None => Ok(Signer {
				rsa: self.rsa.clone(),
				..signer
			}),
		}
	}

	/// The selector of the RSA key this signer also signs with, if any.
	pub fn rsa_selector(&self) -> Option<&str> {
		self.rsa.as_ref().map(|rsa| rsa.selector.as_str())
	}

	/// The selector of the ed25519 key this signer signs with.
	pub fn selector(&self) -> &str {
		&self.selector
	}

	/// The DNS TXT record value publishing this signer's public key.
	pub fn dns_record_value(&self) -> String {
		format!(
			"v=DKIM1; k=ed25519; p={}",
			BASE64.encode(self.key.public_key().as_ref())
		)
	}

	/// The DNS TXT record value for the optional RSA selector, in the form
	/// `v=DKIM1; k=rsa; p=<base64 SubjectPublicKeyInfo DER>`. `None` when no
	/// RSA key is configured. The `p=` value is the SPKI (RFC 6376 §3.6.1),
	/// not the PKCS#1 `RSAPublicKey` ring produces: `openssl rsa -pubout`
	/// prints the same envelope, which is what receivers verify against.
	pub fn rsa_dns_record_value(&self) -> Option<String> {
		Some(rsa_record(&self.rsa.as_ref()?.key))
	}

	/// Sign a raw message for `domain`, returning the full DKIM-Signature
	/// fields (with folding and trailing CRLF) to prepend. `None` when the
	/// message does not carry exactly one From field, its header block is not
	/// UTF-8, or the tag list cannot be written for `domain`.
	pub fn sign(&self, domain: &str, raw: &[u8]) -> Option<String> {
		holder::sign_message(self, domain, raw)
	}

	/// Build one `DKIM-Signature` header line for a given algorithm/selector.
	#[allow(clippy::too_many_arguments)]
	fn one_signature(
		&self,
		algorithm: &str,
		selector: &str,
		domain: &str,
		names: &str,
		body_hash: &str,
		header_input: &str,
		sign: &dyn Fn(&[u8]) -> Option<Vec<u8>>,
	) -> Option<String> {
		let value = wire::unsigned(algorithm, selector, domain, names, body_hash)?;
		let mut dkim_line = canon::header(Canon::Relaxed, "DKIM-Signature", &value);
		dkim_line.truncate(dkim_line.len() - 2);
		let mut hash_input = header_input.to_string();
		hash_input.push_str(&dkim_line);

		let signature = BASE64.encode(sign(hash_input.as_bytes())?);
		wire::finish(value, &signature)
	}
}

/// Generate a fresh ed25519 key, returning (PKCS#8 PEM, DNS record value).
pub fn generate_key() -> Result<(String, String), SignerError> {
	let rng = ring::rand::SystemRandom::new();
	let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
		.map_err(|_| SignerError::InvalidKey("key generation failed".into()))?;
	let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
		.map_err(|_| SignerError::InvalidKey("key generation failed".into()))?;

	let pem = pem_encode(pkcs8.as_ref());

	let record = format!(
		"v=DKIM1; k=ed25519; p={}",
		BASE64.encode(key.public_key().as_ref())
	);
	Ok((pem, record))
}

/// Wrap DER bytes in the PEM envelope a PKCS#8 key is written in, the
/// inverse of [`pem_body`]. The body is base64 in lines of 64 columns.
pub(super) fn pem_encode(der: &[u8]) -> String {
	let body = BASE64.encode(der);
	let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
	for chunk in body.as_bytes().chunks(64) {
		pem.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
		pem.push('\n');
	}
	pem.push_str("-----END PRIVATE KEY-----\n");
	pem
}

/// Load a PKCS#8 PEM ed25519 private key from a file. Shared by DKIM signing
/// and ARC sealing, which use the same key format.
pub(crate) fn load_ed25519_key(key_file: &std::path::Path) -> Result<Ed25519KeyPair, SignerError> {
	let pem = std::fs::read_to_string(key_file).map_err(|source| SignerError::Read {
		path: key_file.display().to_string(),
		source,
	})?;
	let der =
		pem_body(&pem).ok_or_else(|| SignerError::InvalidKey(key_file.display().to_string()))?;
	Ed25519KeyPair::from_pkcs8(&der)
		.map_err(|_| SignerError::InvalidKey(key_file.display().to_string()))
}

pub(crate) fn load_rsa_key(key_file: &std::path::Path) -> Result<RsaKeyPair, SignerError> {
	let pem = std::fs::read_to_string(key_file).map_err(|source| SignerError::Read {
		path: key_file.display().to_string(),
		source,
	})?;
	let der =
		pem_body(&pem).ok_or_else(|| SignerError::InvalidKey(key_file.display().to_string()))?;
	RsaKeyPair::from_pkcs8(&der)
		.map_err(|_| SignerError::InvalidKey(key_file.display().to_string()))
}

/// The DNS TXT record value publishing the RSA key in `key_file`, in the
/// form [`Signer::rsa_dns_record_value`] prints.
pub(crate) fn rsa_record_value(key_file: &std::path::Path) -> Result<String, SignerError> {
	Ok(rsa_record(&load_rsa_key(key_file)?))
}

fn rsa_record(key: &RsaKeyPair) -> String {
	let spki = super::spki::spki_for_rsa(key.public_key().as_ref());
	format!("v=DKIM1; k=rsa; p={}", BASE64.encode(spki))
}

/// RSASSA-PKCS1-v1_5 over SHA-256, the RSA variant DKIM uses.
fn rsa_sign(key: &RsaKeyPair, input: &[u8]) -> Option<Vec<u8>> {
	let mut signature = vec![0u8; key.public().modulus_len()];
	key.sign(
		&RSA_PKCS1_SHA256,
		&SystemRandom::new(),
		input,
		&mut signature,
	)
	.ok()?;
	Some(signature)
}

/// Extract the DER body of a single-block PEM file.
pub(super) fn pem_body(pem: &str) -> Option<Vec<u8>> {
	let mut body = String::new();
	let mut inside = false;
	for line in pem.lines() {
		if line.starts_with("-----BEGIN ") {
			inside = true;
			continue;
		}
		if line.starts_with("-----END ") {
			break;
		}
		if inside {
			body.push_str(line.trim());
		}
	}
	if body.is_empty() {
		return None;
	}
	BASE64.decode(body).ok()
}

#[cfg(test)]
mod tests;
