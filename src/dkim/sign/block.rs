//! The half of DKIM signing that reads the message.
//!
//! It turns a raw message into a [`HeaderBlock`]: the names that go into
//! `h=`, the relaxed canonical form of the fields they select, and the hash
//! of the canonical body. That block is everything a key holder needs to
//! sign, and it carries no byte of the body, so the half that holds the
//! private key never parses the message (`docs/operations/serve-split.md`).

use super::{OVERSIGNED_HEADERS, SIGNED_HEADERS};
use crate::dkim::canon;
use crate::dkim::signature::Canon;

/// What a DKIM signature covers, minus the tag list the key holder writes.
///
/// Built by [`HeaderBlock::from_message`], which is the only way the signing
/// path makes one; [`HeaderBlock::check`] is what a key holder runs on a
/// block it did not build, so a malformed one is refused before it is
/// signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderBlock {
	/// The `h=` value: field names, lowercase, joined by `:`, the selected
	/// fields bottom-up and then the oversigned names.
	pub(crate) names: String,
	/// The relaxed canonical form of each selected field, in the order of
	/// `names`, one CRLF-terminated line per field.
	pub(crate) canonical: String,
	/// SHA-256 of the relaxed canonical body, the value `bh=` carries.
	pub(crate) body_hash: [u8; 32],
}

/// Why a [`HeaderBlock`] is refused before it is signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Malformed {
	/// `names` is empty or holds a name that cannot appear in `h=`.
	#[error("a field name in h= is empty, uppercase or not a valid field name")]
	Name,
	/// A canonical line is not `name:value` ending in a single CRLF.
	#[error("a canonical field is not one line ending in CRLF")]
	Line,
	/// The canonical lines do not name the leading entries of `names`, in
	/// the same order.
	#[error("the canonical fields do not match the names in h=")]
	Order,
	/// The block does not carry exactly one `From` field.
	#[error("the block does not carry exactly one From field")]
	From,
}

impl HeaderBlock {
	/// Read `raw` into the block a key holder signs. `None` when the header
	/// block is not UTF-8, when a field has no colon, or when the message
	/// does not carry exactly one `From` field: the send-as check and DMARC
	/// both read that one field, so a signature over two would sign the
	/// one neither of them looked at.
	pub fn from_message(raw: &[u8]) -> Option<Self> {
		let (headers, body) = split_message(raw)?;
		let from_fields = headers
			.iter()
			.filter(|(name, _)| name.eq_ignore_ascii_case("from"))
			.count();
		if from_fields != 1 {
			return None;
		}
		let canonical_body = canon::body(Canon::Relaxed, body);
		let body_hash = ring::digest::digest(&ring::digest::SHA256, &canonical_body);

		// Consume every selected instance bottom-up (RFC 6376 section 5.4.2).
		let unsafe_resent = collect_unsafe_resent_names(raw);
		let mut signed_names = Vec::new();
		let mut canonical = String::new();
		for (header_name, header_value) in headers.iter().rev() {
			let name = header_name.to_ascii_lowercase();
			let known = SIGNED_HEADERS.contains(&name.as_str());
			let resent = !known
				&& name.starts_with("resent-")
				&& is_safe_header_name(&name)
				&& !unsafe_resent.contains(&name);
			if known || resent {
				signed_names.push(name);
				canonical.push_str(&canon::header(Canon::Relaxed, header_name, header_value));
			}
		}
		// Absent instances contribute no bytes, but prevent later additions.
		signed_names.extend(OVERSIGNED_HEADERS.iter().map(|name| (*name).to_string()));
		Some(HeaderBlock {
			names: signed_names.join(":"),
			canonical,
			body_hash: body_hash.as_ref().try_into().ok()?,
		})
	}

	/// Check the shape a key holder relies on: every name valid and
	/// lowercase, every canonical line one `name:value` CRLF line, the lines
	/// naming the leading entries of `names` in order, and exactly one
	/// `from` line among them.
	pub fn check(&self) -> Result<(), Malformed> {
		let names: Vec<&str> = self.names.split(':').collect();
		if names
			.iter()
			.any(|name| !is_safe_header_name(name) || name.bytes().any(|b| b.is_ascii_uppercase()))
		{
			return Err(Malformed::Name);
		}
		let mut from_lines = 0;
		for (index, line) in self.canonical.split_inclusive("\r\n").enumerate() {
			let content = line.strip_suffix("\r\n").ok_or(Malformed::Line)?;
			if content.contains(['\r', '\n']) {
				return Err(Malformed::Line);
			}
			let (name, _) = content.split_once(':').ok_or(Malformed::Line)?;
			if names.get(index) != Some(&name) {
				return Err(Malformed::Order);
			}
			if name == "from" {
				from_lines += 1;
			}
		}
		if from_lines != 1 {
			return Err(Malformed::From);
		}
		Ok(())
	}
}

/// Header (name, value) pairs of a message.
type HeaderPairs<'a> = Vec<(&'a str, &'a str)>;

/// Split raw message into header (name, value) pairs and body.
fn split_message(raw: &[u8]) -> Option<(HeaderPairs<'_>, &[u8])> {
	let (raw_block, body) = crate::util::header_block::split_at_blank_line(raw);
	let block = std::str::from_utf8(raw_block).ok()?;

	let mut headers = Vec::new();
	let mut current: Option<(usize, usize)> = None;
	let mut offset = 0;
	for line in block.split_inclusive('\n') {
		let start = offset;
		offset += line.len();
		let had_line_feed = line.ends_with('\n');
		let content = line.strip_suffix('\n').unwrap_or(line);
		let content = if had_line_feed {
			content.strip_suffix('\r').unwrap_or(content)
		} else {
			content
		};
		if content.starts_with(' ') || content.starts_with('\t') {
			if let Some((_, end)) = &mut current {
				*end = offset;
			}
			continue;
		}
		if let Some((from, to)) = current.take() {
			headers.push(&block[from..to]);
		}
		if !content.is_empty() {
			current = Some((start, offset));
		}
	}
	if let Some((from, to)) = current.take() {
		headers.push(&block[from..to]);
	}

	let mut parsed = Vec::with_capacity(headers.len());
	for header in headers {
		let had_line_feed = header.ends_with('\n');
		let header = header.strip_suffix('\n').unwrap_or(header);
		let header = if had_line_feed {
			header.strip_suffix('\r').unwrap_or(header)
		} else {
			header
		};
		let colon = header.find(':')?;
		parsed.push((header[..colon].trim_end(), &header[colon + 1..]));
	}
	Some((parsed, body))
}

/// Field names from the message that begin with `Resent-` but cannot appear
/// verbatim in a DKIM `h=` tag: a name with `:` or `;` would terminate the
/// tag or split it, and RFC 5322 §2.2 only allows printable US-ASCII without
/// `:`. The names are read from the raw bytes so a malformed one with
/// trailing whitespace that `split_message` would otherwise trim is still
/// caught.
fn collect_unsafe_resent_names(raw: &[u8]) -> std::collections::HashSet<String> {
	let mut unsafe_names = std::collections::HashSet::new();
	// Only the header block is read: a line of the body that looks like a
	// field must not change what the signature covers.
	let end = crate::util::header_block::split_at_blank_line(raw).0.len();
	for raw_line in raw[..end].split(|&b| b == b'\r' || b == b'\n') {
		if raw_line
			.first()
			.is_none_or(|byte| matches!(byte, b' ' | b'\t'))
		{
			continue;
		}
		let Ok(line) = std::str::from_utf8(raw_line) else {
			continue;
		};
		let Some((raw_name, _)) = line.split_once(':') else {
			continue;
		};
		if !is_safe_header_name(raw_name) {
			let trimmed = raw_name.trim_end().to_ascii_lowercase();
			if trimmed.starts_with("resent-") {
				unsafe_names.insert(trimmed);
			}
		}
	}
	unsafe_names
}

/// Whether `name` can be written into the DKIM `h=` tag. RFC 5322 §2.2
/// restricts field names to printable US-ASCII without `:`; DKIM §3.2 adds
/// `;` as the tag separator, so the name cannot contain one either.
pub(super) fn is_safe_header_name(name: &str) -> bool {
	!name.is_empty()
		&& name
			.bytes()
			.all(|b| (33..=126).contains(&b) && b != b':' && b != b';')
}
