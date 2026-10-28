//! `DKIM-Signature` header parsing (RFC 6376 section 3.5) and the rule each
//! signing algorithm follows about which bytes its signature covers.

use std::borrow::Cow;

/// Canonicalization mode (RFC 6376 section 3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Canon {
	Simple,
	Relaxed,
}

/// Signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
	RsaSha256,
	Ed25519Sha256,
}

impl Algorithm {
	/// The bytes a signature of this algorithm covers, given the canonicalized
	/// signing input.
	///
	/// `rsa-sha256` hashes the input inside the PKCS#1 v1.5 padding, so its
	/// signature covers the input itself. `ed25519-sha256` (RFC 8463 section
	/// 3) computes a SHA-256 digest of the input and signs that digest,
	/// because PureEdDSA has no hash step of its own.
	///
	/// The signer and the verifier both ask here, so the two cannot drift
	/// apart on which bytes the signature covers.
	pub fn signed_bytes<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
		match self {
			Algorithm::RsaSha256 => Cow::Borrowed(input),
			Algorithm::Ed25519Sha256 => Cow::Owned(
				ring::digest::digest(&ring::digest::SHA256, input)
					.as_ref()
					.to_vec(),
			),
		}
	}
}

/// A parsed DKIM-Signature header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
	pub algorithm: Algorithm,
	pub domain: String,
	pub selector: String,
	pub signed_headers: Vec<String>,
	pub body_hash: Vec<u8>,
	pub signature: Vec<u8>,
	pub header_canon: Canon,
	pub body_canon: Canon,
	/// `l=` body length limit, if present.
	pub body_length: Option<usize>,
	/// `x=` expiration (UNIX seconds), if present.
	pub expiration: Option<u64>,
}

/// Why a signature header could not be used: always a permerror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureError(pub String);

/// Parse the value of a `DKIM-Signature` header.
pub fn parse(value: &str) -> Result<Signature, SignatureError> {
	let mut version = None;
	let mut algorithm = None;
	let mut domain = None;
	let mut selector = None;
	let mut signed_headers = None;
	let mut body_hash = None;
	let mut signature = None;
	let mut header_canon = Canon::Simple;
	let mut body_canon = Canon::Simple;
	let mut body_length = None;
	let mut expiration = None;

	for tag in value.split(';') {
		let tag = tag.trim();
		if tag.is_empty() {
			continue;
		}
		let (name, tag_value) = tag
			.split_once('=')
			.ok_or_else(|| SignatureError(format!("malformed tag \"{tag}\"")))?;
		// Tag values may contain folding whitespace; strip it all.
		let compact: String = tag_value.chars().filter(|c| !c.is_whitespace()).collect();
		match name.trim() {
			"v" => version = Some(compact),
			"a" => {
				algorithm = Some(match compact.as_str() {
					"rsa-sha256" => Algorithm::RsaSha256,
					"ed25519-sha256" => Algorithm::Ed25519Sha256,
					other => {
						return Err(SignatureError(format!("unsupported algorithm {other}")));
					}
				});
			}
			"d" => domain = Some(compact.to_ascii_lowercase()),
			"s" => selector = Some(compact.to_ascii_lowercase()),
			"h" => {
				signed_headers = Some(
					compact
						.split(':')
						.map(|h| h.to_ascii_lowercase())
						.collect::<Vec<_>>(),
				);
			}
			"bh" => body_hash = Some(decode_base64(&compact, "bh")?),
			"b" => signature = Some(decode_base64(&compact, "b")?),
			"c" => {
				let (header, body) = compact
					.split_once('/')
					.unwrap_or((compact.as_str(), "simple"));
				header_canon = parse_canon(header)?;
				body_canon = parse_canon(body)?;
			}
			"l" => {
				body_length = Some(
					compact
						.parse()
						.map_err(|_| SignatureError("invalid l= tag".into()))?,
				);
			}
			"x" => {
				expiration = Some(
					compact
						.parse()
						.map_err(|_| SignatureError("invalid x= tag".into()))?,
				);
			}
			// Unknown tags must be ignored (section 3.2).
			_ => {}
		}
	}

	if version.as_deref() != Some("1") {
		return Err(SignatureError("v= must be 1".into()));
	}
	let signed_headers = signed_headers.ok_or_else(|| SignatureError("missing h= tag".into()))?;
	// The From header must be signed (section 5.4).
	if !signed_headers.iter().any(|h| h == "from") {
		return Err(SignatureError("h= does not cover From".into()));
	}
	Ok(Signature {
		algorithm: algorithm.ok_or_else(|| SignatureError("missing a= tag".into()))?,
		domain: domain.ok_or_else(|| SignatureError("missing d= tag".into()))?,
		selector: selector.ok_or_else(|| SignatureError("missing s= tag".into()))?,
		signed_headers,
		body_hash: body_hash.ok_or_else(|| SignatureError("missing bh= tag".into()))?,
		signature: signature.ok_or_else(|| SignatureError("missing b= tag".into()))?,
		header_canon,
		body_canon,
		body_length,
		expiration,
	})
}

fn parse_canon(text: &str) -> Result<Canon, SignatureError> {
	match text {
		"simple" => Ok(Canon::Simple),
		"relaxed" => Ok(Canon::Relaxed),
		other => Err(SignatureError(format!("unknown canonicalization {other}"))),
	}
}

fn decode_base64(text: &str, tag: &str) -> Result<Vec<u8>, SignatureError> {
	use base64::Engine;
	base64::engine::general_purpose::STANDARD
		.decode(text)
		.map_err(|_| SignatureError(format!("invalid base64 in {tag}= tag")))
}

#[cfg(test)]
mod tests;
