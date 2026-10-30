//! ARC-Message-Signature (AMS) signing and verification (RFC 8617 §5.1.1).
//!
//! The AMS signs the message headers and body exactly like a DKIM signature,
//! so this reuses DKIM's canonicalization and public-key record format. We
//! always sign with relaxed/relaxed ed25519; verification honours the `c=`
//! the signer declared and the algorithm it declared too: an
//! `a=ed25519-sha256` header is verified with Ed25519 and an `a=rsa-sha256`
//! header with RSA.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ring::signature::Ed25519KeyPair;

use crate::dkim::{Algorithm, Canon, DkimOutcome, canon};
use crate::spf::{DnsFailure, DnsLookup};

use super::key::KeyRecord;
use super::signature::MessageSignature;

/// Headers signed when present, lowest occurrence first (RFC 6376 §5.4).
const SIGNED_HEADERS: [&str; 6] = ["from", "to", "cc", "subject", "date", "message-id"];

/// Build the `ARC-Message-Signature` header line for `instance`, signing the
/// message with relaxed/relaxed ed25519. Returns `None` if From is absent.
pub fn build(
	key: &Ed25519KeyPair,
	instance: u32,
	domain: &str,
	selector: &str,
	raw_message: &[u8],
) -> Option<String> {
	let (headers, body) = split_message(raw_message)?;

	let canonical_body = canon::body(Canon::Relaxed, &body);
	let body_hash = BASE64.encode(ring::digest::digest(&ring::digest::SHA256, &canonical_body));

	let mut signed_names = Vec::new();
	let mut used = vec![false; headers.len()];
	let mut hash_input = String::new();
	for name in SIGNED_HEADERS {
		if let Some(index) = lowest_unused(&headers, &used, name) {
			used[index] = true;
			signed_names.push(name.to_string());
			hash_input.push_str(&canon::header(
				Canon::Relaxed,
				&headers[index].0,
				&headers[index].1,
			));
		}
	}
	if !signed_names.iter().any(|n| n == "from") {
		return None;
	}

	let value = format!(
		" i={instance}; a=ed25519-sha256; c=relaxed/relaxed; d={domain}; s={selector}; \
h={}; bh={body_hash}; b=",
		signed_names.join(":"),
	);
	let mut self_line = canon::header(Canon::Relaxed, "ARC-Message-Signature", &value);
	self_line.truncate(self_line.len() - 2); // drop trailing CRLF
	hash_input.push_str(&self_line);

	// RFC 8463 section 3: an Ed25519-SHA256 signature covers the SHA-256
	// digest of the signed data, not the data itself.
	let signed = Algorithm::Ed25519Sha256.signed_bytes(hash_input.as_bytes());
	let signature = BASE64.encode(key.sign(signed.as_ref()).as_ref());
	Some(format!("ARC-Message-Signature:{value}{signature}\r\n"))
}

/// Verify the AMS `ams` (with the raw header value `raw_value`) against the
/// message. Returns a DKIM-style outcome.
pub async fn verify(
	dns: &dyn DnsLookup,
	ams: &MessageSignature,
	raw_value: &str,
	raw_message: &[u8],
) -> DkimOutcome {
	let Some((headers, body)) = split_message(raw_message) else {
		return DkimOutcome::PermError;
	};

	// Body hash first: cheap rejection without DNS.
	let canonical_body = canon::body(ams.body_canon, &body);
	let body_hash = ring::digest::digest(&ring::digest::SHA256, &canonical_body);
	if body_hash.as_ref() != ams.body_hash.as_slice() {
		return DkimOutcome::Fail;
	}

	let hash_input = header_hash_input(ams.header_canon, &headers, &ams.signed_headers, raw_value);

	let key_name = format!("{}._domainkey.{}", ams.selector, ams.domain);
	let texts = match dns.txt(&key_name).await {
		Ok(texts) => texts,
		Err(DnsFailure::Temporary) => return DkimOutcome::TempError,
	};
	let record = match KeyRecord::first(&texts) {
		Ok(record) => record,
		Err(_) => return DkimOutcome::PermError,
	};
	// The algorithm the header declares decides the primitive and the shape
	// of the key, and the record has to publish a key of that type.
	let key = match record.verification_key(ams.algorithm) {
		Ok(key) => key,
		Err(_) => return DkimOutcome::PermError,
	};

	// The same rule the signer followed: an Ed25519-SHA256 signature covers
	// the SHA-256 digest of the signed data.
	let signed = ams.algorithm.signed_bytes(hash_input.as_bytes());
	if key.verify(signed.as_ref(), &ams.signature) {
		DkimOutcome::Pass
	} else {
		DkimOutcome::Fail
	}
}

/// Build the hash input for verification: the signed headers bottom-up, then
/// the AMS header itself with its `b=` value stripped and no trailing CRLF.
fn header_hash_input(
	canon_mode: Canon,
	headers: &[(String, String)],
	signed: &[String],
	raw_value: &str,
) -> String {
	let mut used = vec![false; headers.len()];
	let mut input = String::new();
	for name in signed {
		if let Some(index) = lowest_unused(headers, &used, name) {
			used[index] = true;
			input.push_str(&canon::header(
				canon_mode,
				&headers[index].0,
				&headers[index].1,
			));
		}
	}
	let stripped = strip_b(raw_value);
	let mut self_line = canon::header(canon_mode, "ARC-Message-Signature", &stripped);
	if self_line.ends_with("\r\n") {
		self_line.truncate(self_line.len() - 2);
	}
	input.push_str(&self_line);
	input
}

/// Index of the lowest (last) header named `name` not yet used.
fn lowest_unused(headers: &[(String, String)], used: &[bool], name: &str) -> Option<usize> {
	headers
		.iter()
		.enumerate()
		.rev()
		.find(|(i, (header_name, _))| !used[*i] && header_name.eq_ignore_ascii_case(name))
		.map(|(i, _)| i)
}

/// Remove the value after `b=`, keeping the tag (RFC 6376 §3.7).
pub(crate) fn strip_b(value: &str) -> String {
	value
		.split(';')
		.map(|tag| {
			let trimmed = tag.trim_start();
			if trimmed.starts_with("b=") {
				let prefix = tag.len() - trimmed.len();
				format!("{}b=", &tag[..prefix])
			} else {
				tag.to_string()
			}
		})
		.collect::<Vec<_>>()
		.join(";")
}

/// Unfolded headers `(name, value)` plus the message body.
type SplitMessage = (Vec<(String, String)>, Vec<u8>);

/// Split a raw message into unfolded `(name, value)` headers and the body.
fn split_message(raw: &[u8]) -> Option<SplitMessage> {
	let block_end = raw.windows(4).position(|w| w == b"\r\n\r\n");
	let (header_end, body_start) = match block_end {
		Some(pos) => (pos + 2, pos + 4),
		None => (raw.len(), raw.len()),
	};
	let block = std::str::from_utf8(&raw[..header_end]).ok()?;
	let body = raw.get(body_start..).unwrap_or(&[]).to_vec();

	let mut headers: Vec<(String, String)> = Vec::new();
	let mut current: Option<String> = None;
	for line in block.split_inclusive("\r\n") {
		let content = line.strip_suffix("\r\n").unwrap_or(line);
		if content.starts_with(' ') || content.starts_with('\t') {
			if let Some(buffer) = &mut current {
				buffer.push_str(content);
			}
			continue;
		}
		if let Some(buffer) = current.take() {
			push_header(&mut headers, &buffer);
		}
		if !content.is_empty() {
			current = Some(content.to_string());
		}
	}
	if let Some(buffer) = current.take() {
		push_header(&mut headers, &buffer);
	}
	Some((headers, body))
}

fn push_header(headers: &mut Vec<(String, String)>, line: &str) {
	if let Some(colon) = line.find(':') {
		let name = line[..colon].trim_end().to_string();
		let value = line[colon + 1..].to_string();
		headers.push((name, value));
	}
}

/// Names this parser reads out of a raw message, with the `trim_end` it
/// applies on each header name. Tests use it to confirm the real ARC-AMS
/// parser agrees with the inbound trust-field stripper about whether a
/// reserved name survived.
#[cfg(test)]
pub(crate) fn header_names(raw: &[u8]) -> Vec<String> {
	split_message(raw)
		.map(|(headers, _)| headers.into_iter().map(|(name, _)| name).collect())
		.unwrap_or_default()
}
