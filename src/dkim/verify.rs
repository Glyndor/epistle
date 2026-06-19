//! DKIM signature verification (RFC 6376 section 6).

use ring::signature::{ED25519, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};

use crate::spf::{DnsFailure, DnsLookup};

use super::canon;
use super::signature::Algorithm;

/// Outcome of one signature (RFC 8601 keywords).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkimOutcome {
	Pass,
	Fail,
	PermError,
	TempError,
	None,
}

impl DkimOutcome {
	/// Lowercase keyword for `Authentication-Results`.
	pub fn as_str(self) -> &'static str {
		match self {
			DkimOutcome::Pass => "pass",
			DkimOutcome::Fail => "fail",
			DkimOutcome::PermError => "permerror",
			DkimOutcome::TempError => "temperror",
			DkimOutcome::None => "none",
		}
	}
}

/// Result for one DKIM-Signature header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimResult {
	pub outcome: DkimOutcome,
	/// `d=` domain, when the header parsed far enough to know it.
	pub domain: Option<String>,
}

/// Verify every DKIM-Signature header of a raw message. An unsigned message
/// yields a single `none` result.
pub async fn verify_message(dns: &dyn DnsLookup, raw: &[u8]) -> Vec<DkimResult> {
	let Some(message) = Message::split(raw) else {
		return vec![DkimResult {
			outcome: DkimOutcome::PermError,
			domain: None,
		}];
	};

	let signatures: Vec<(usize, &Header)> = message
		.headers
		.iter()
		.enumerate()
		.filter(|(_, header)| header.name.eq_ignore_ascii_case("DKIM-Signature"))
		.collect();
	if signatures.is_empty() {
		return vec![DkimResult {
			outcome: DkimOutcome::None,
			domain: None,
		}];
	}

	let mut results = Vec::with_capacity(signatures.len());
	for (index, header) in signatures {
		results.push(verify_one(dns, &message, index, header.value).await);
	}
	results
}

async fn verify_one(
	dns: &dyn DnsLookup,
	message: &Message<'_>,
	signature_index: usize,
	signature_value: &str,
) -> DkimResult {
	let signature = match super::signature::parse(signature_value) {
		Ok(signature) => signature,
		Err(_) => {
			return DkimResult {
				outcome: DkimOutcome::PermError,
				domain: None,
			};
		}
	};
	let domain = Some(signature.domain.clone());

	// Expiry check: reject signatures past their x= timestamp before DNS.
	if let Some(exp) = signature.expiration {
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs();
		if now > exp {
			return DkimResult {
				outcome: DkimOutcome::Fail,
				domain,
			};
		}
	}

	// Body hash first: cheap rejection without DNS.
	let limited = match signature.body_length {
		Some(length) if length <= message.body.len() => &message.body[..length],
		Some(_) => {
			return DkimResult {
				outcome: DkimOutcome::PermError,
				domain,
			};
		}
		None => message.body,
	};
	let canonical_body = canon::body(signature.body_canon, limited);
	let body_hash = ring::digest::digest(&ring::digest::SHA256, &canonical_body);
	if body_hash.as_ref() != signature.body_hash.as_slice() {
		return DkimResult {
			outcome: DkimOutcome::Fail,
			domain,
		};
	}

	// Build the signed header block (section 3.7): listed headers from the
	// bottom up, then the DKIM-Signature itself with b= emptied.
	let mut hash_input = String::new();
	let mut used: Vec<bool> = vec![false; message.headers.len()];
	for name in &signature.signed_headers {
		if let Some(index) = message
			.headers
			.iter()
			.enumerate()
			.rev()
			.position(|(i, header)| !used[i] && header.name.eq_ignore_ascii_case(name))
			.map(|rev_position| message.headers.len() - 1 - rev_position)
		{
			used[index] = true;
			let header = &message.headers[index];
			hash_input.push_str(&canon::header(
				signature.header_canon,
				header.name,
				header.value,
			));
		}
		// A listed but absent header contributes nothing (section 5.4.2).
	}
	let dkim_header = &message.headers[signature_index];
	let unsigned_value = strip_b_tag(dkim_header.value);
	let mut dkim_line = canon::header(signature.header_canon, dkim_header.name, &unsigned_value);
	// The DKIM-Signature line is included without its trailing CRLF.
	if dkim_line.ends_with("\r\n") {
		dkim_line.truncate(dkim_line.len() - 2);
	}
	hash_input.push_str(&dkim_line);

	// Fetch the public key.
	let key_name = format!("{}._domainkey.{}", signature.selector, signature.domain);
	let texts = match dns.txt(&key_name).await {
		Ok(texts) => texts,
		Err(DnsFailure::Temporary) => {
			return DkimResult {
				outcome: DkimOutcome::TempError,
				domain,
			};
		}
	};
	let Some(key) = texts.iter().find_map(|text| parse_key(text)) else {
		return DkimResult {
			outcome: DkimOutcome::PermError,
			domain,
		};
	};

	let algorithm: &dyn ring::signature::VerificationAlgorithm = match signature.algorithm {
		Algorithm::RsaSha256 => &RSA_PKCS1_2048_8192_SHA256,
		Algorithm::Ed25519Sha256 => &ED25519,
	};
	let public_key = UnparsedPublicKey::new(algorithm, key);
	let outcome = match public_key.verify(hash_input.as_bytes(), &signature.signature) {
		Ok(()) => DkimOutcome::Pass,
		Err(_) => DkimOutcome::Fail,
	};
	DkimResult { outcome, domain }
}

/// Extract the `p=` public key from a key record.
pub(crate) fn parse_key(text: &str) -> Option<Vec<u8>> {
	use base64::Engine;
	for tag in text.split(';') {
		let tag = tag.trim();
		if let Some(value) = tag.strip_prefix("p=") {
			let compact: String = value.chars().filter(|c| !c.is_whitespace()).collect();
			return base64::engine::general_purpose::STANDARD
				.decode(compact)
				.ok();
		}
	}
	None
}

/// Remove the value of the `b=` tag, keeping the tag itself (section 3.7).
fn strip_b_tag(value: &str) -> String {
	value
		.split(';')
		.map(|tag| {
			let trimmed = tag.trim_start();
			if trimmed.starts_with("b=") || trimmed.starts_with("b =") {
				let prefix_len = tag.len() - trimmed.len();
				format!("{}b=", &tag[..prefix_len])
			} else {
				tag.to_string()
			}
		})
		.collect::<Vec<_>>()
		.join(";")
}

/// A raw message split into headers and body.
struct Message<'a> {
	headers: Vec<Header<'a>>,
	body: &'a [u8],
}

struct Header<'a> {
	name: &'a str,
	value: &'a str,
}

impl<'a> Message<'a> {
	/// Split a raw RFC 5322 message. Returns `None` on malformed headers.
	fn split(raw: &'a [u8]) -> Option<Self> {
		let text_end = find_body_start(raw);
		let header_block = std::str::from_utf8(&raw[..text_end.0]).ok()?;
		let body = &raw[text_end.1..];

		let mut headers = Vec::new();
		let mut current: Option<(usize, usize)> = None;
		let mut offset = 0;
		for line in header_block.split_inclusive("\r\n") {
			let line_start = offset;
			offset += line.len();
			let content = line.strip_suffix("\r\n").unwrap_or(line);
			if content.starts_with(' ') || content.starts_with('\t') {
				// Folded continuation of the current header.
				if let Some((_, end)) = &mut current {
					*end = offset;
				} else {
					return None;
				}
				continue;
			}
			if let Some((start, end)) = current.take() {
				headers.push(parse_header(&header_block[start..end])?);
			}
			if !content.is_empty() {
				current = Some((line_start, offset));
			}
		}
		if let Some((start, end)) = current.take() {
			headers.push(parse_header(&header_block[start..end])?);
		}
		Some(Message { headers, body })
	}
}

fn parse_header(raw: &str) -> Option<Header<'_>> {
	let raw = raw.strip_suffix("\r\n").unwrap_or(raw);
	let colon = raw.find(':')?;
	let (name, rest) = raw.split_at(colon);
	Some(Header {
		name: name.trim_end(),
		value: &rest[1..],
	})
}

/// Returns (end of header block, start of body).
fn find_body_start(raw: &[u8]) -> (usize, usize) {
	let mut index = 0;
	while index + 3 < raw.len() {
		if &raw[index..index + 4] == b"\r\n\r\n" {
			return (index + 2, index + 4);
		}
		index += 1;
	}
	(raw.len(), raw.len())
}

#[cfg(test)]
#[path = "verify_tests.rs"]
pub(crate) mod tests;
