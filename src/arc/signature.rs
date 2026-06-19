//! Parsing of the two signed ARC headers (RFC 8617 §4.1.2, §4.1.3):
//! `ARC-Message-Signature` (AMS) and `ARC-Seal` (AS).
//!
//! AMS mirrors a DKIM-Signature (it signs the message headers and body) but
//! carries an `i=` instance and no `v=`. AS signs the ARC header set instead of
//! the body, so it has neither `h=` nor `bh=`, but it does carry the `cv=`
//! chain-validation status. Both reuse DKIM's algorithm and canonicalization
//! definitions.

use crate::dkim::{Algorithm, Canon};

use super::chain::ChainValidation;

/// A parsed `ARC-Message-Signature` header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSignature {
	pub instance: u32,
	pub algorithm: Algorithm,
	pub domain: String,
	pub selector: String,
	pub signed_headers: Vec<String>,
	pub body_hash: Vec<u8>,
	pub signature: Vec<u8>,
	pub header_canon: Canon,
	pub body_canon: Canon,
	pub timestamp: Option<u64>,
}

/// A parsed `ARC-Seal` header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seal {
	pub instance: u32,
	pub algorithm: Algorithm,
	pub domain: String,
	pub selector: String,
	pub chain_validation: ChainValidation,
	pub signature: Vec<u8>,
	pub timestamp: Option<u64>,
}

/// Why an ARC header could not be parsed: always a permerror for the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureError(pub String);

/// Common tag bag: name → whitespace-stripped value, in encounter order.
struct Tags(Vec<(String, String)>);

impl Tags {
	fn parse(value: &str) -> Result<Tags, SignatureError> {
		let mut tags = Vec::new();
		for tag in value.split(';') {
			let tag = tag.trim();
			if tag.is_empty() {
				continue;
			}
			let (name, raw) = tag
				.split_once('=')
				.ok_or_else(|| SignatureError(format!("malformed tag \"{tag}\"")))?;
			let compact: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
			tags.push((name.trim().to_ascii_lowercase(), compact));
		}
		Ok(Tags(tags))
	}

	fn get(&self, key: &str) -> Option<&str> {
		self.0
			.iter()
			.find(|(name, _)| name == key)
			.map(|(_, value)| value.as_str())
	}

	fn require(&self, key: &str) -> Result<&str, SignatureError> {
		self.get(key)
			.ok_or_else(|| SignatureError(format!("missing {key}= tag")))
	}
}

fn parse_instance(text: &str) -> Result<u32, SignatureError> {
	let instance: u32 = text
		.parse()
		.map_err(|_| SignatureError("invalid i= tag".into()))?;
	if instance == 0 || instance > super::chain::MAX_INSTANCE {
		return Err(SignatureError("i= out of range".into()));
	}
	Ok(instance)
}

fn parse_algorithm(text: &str) -> Result<Algorithm, SignatureError> {
	match text {
		"rsa-sha256" => Ok(Algorithm::RsaSha256),
		"ed25519-sha256" => Ok(Algorithm::Ed25519Sha256),
		other => Err(SignatureError(format!("unsupported algorithm {other}"))),
	}
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

fn parse_timestamp(tags: &Tags) -> Result<Option<u64>, SignatureError> {
	match tags.get("t") {
		Some(value) => Ok(Some(
			value
				.parse()
				.map_err(|_| SignatureError("invalid t= tag".into()))?,
		)),
		None => Ok(None),
	}
}

/// Parse an `ARC-Message-Signature` value.
pub fn parse_message_signature(value: &str) -> Result<MessageSignature, SignatureError> {
	let tags = Tags::parse(value)?;
	let instance = parse_instance(tags.require("i")?)?;
	let algorithm = parse_algorithm(tags.require("a")?)?;
	let signed_headers: Vec<String> = tags
		.require("h")?
		.split(':')
		.map(|h| h.to_ascii_lowercase())
		.collect();
	// The From header must be signed, as in DKIM (RFC 8617 §4.1.2).
	if !signed_headers.iter().any(|h| h == "from") {
		return Err(SignatureError("h= does not cover From".into()));
	}
	// ARC headers must not be signed by the AMS (RFC 8617 §4.1.2).
	if signed_headers.iter().any(|h| h.starts_with("arc-")) {
		return Err(SignatureError("h= must not cover ARC headers".into()));
	}
	let (header_canon, body_canon) = match tags.get("c") {
		Some(c) => {
			let (header, body) = c.split_once('/').unwrap_or((c, "simple"));
			(parse_canon(header)?, parse_canon(body)?)
		}
		None => (Canon::Simple, Canon::Simple),
	};
	Ok(MessageSignature {
		instance,
		algorithm,
		domain: tags.require("d")?.to_ascii_lowercase(),
		selector: tags.require("s")?.to_ascii_lowercase(),
		signed_headers,
		body_hash: decode_base64(tags.require("bh")?, "bh")?,
		signature: decode_base64(tags.require("b")?, "b")?,
		header_canon,
		body_canon,
		timestamp: parse_timestamp(&tags)?,
	})
}

/// Parse an `ARC-Seal` value.
pub fn parse_seal(value: &str) -> Result<Seal, SignatureError> {
	let tags = Tags::parse(value)?;
	// The seal signs the ARC set, never the body: h= and bh= are forbidden.
	if tags.get("h").is_some() || tags.get("bh").is_some() {
		return Err(SignatureError("ARC-Seal must not carry h= or bh=".into()));
	}
	let chain_validation = ChainValidation::parse(tags.require("cv")?)
		.ok_or_else(|| SignatureError("invalid cv= tag".into()))?;
	Ok(Seal {
		instance: parse_instance(tags.require("i")?)?,
		algorithm: parse_algorithm(tags.require("a")?)?,
		domain: tags.require("d")?.to_ascii_lowercase(),
		selector: tags.require("s")?.to_ascii_lowercase(),
		chain_validation,
		signature: decode_base64(tags.require("b")?, "b")?,
		timestamp: parse_timestamp(&tags)?,
	})
}
