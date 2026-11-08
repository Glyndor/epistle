//! Helpers that quote, size-check and sanitize what the client sends and
//! prints. Split from `mod.rs`.

use super::ClientError;

/// `value` as an IMAP quoted string.
pub(super) fn quote(value: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(value.len() + 2);
	out.push(b'"');
	for &byte in value {
		if matches!(byte, b'"' | b'\\') {
			out.push(b'\\');
		}
		out.push(byte);
	}
	out.push(b'"');
	out
}

/// A mailbox name as a quoted string, refusing what a quoted string
/// cannot carry.
pub(super) fn quote_mailbox(name: &[u8]) -> Result<Vec<u8>, ClientError> {
	if name.iter().any(|&b| matches!(b, b'\0' | b'\r' | b'\n')) {
		return Err(ClientError::Unsendable(
			"the mailbox name contains a NUL or line break",
		));
	}
	Ok(quote(name))
}

/// Whether a body of `actual` octets is close enough to the `declared`
/// RFC822.SIZE: servers count line endings or trailing octets slightly
/// differently, so a tenth plus 4 KiB more is tolerated, nothing beyond.
pub(crate) fn size_fits(declared: u64, actual: u64) -> bool {
	actual <= declared.saturating_add(declared / 10).saturating_add(4096)
}

/// A compact UID set for sorted `uids`: runs become `a:b`.
pub(crate) fn uid_set(uids: &[u32]) -> String {
	let mut out = String::new();
	let mut at = 0;
	while at < uids.len() {
		let start = uids[at];
		let mut end = start;
		while at + 1 < uids.len() && uids[at + 1] == end + 1 {
			at += 1;
			end = uids[at];
		}
		if !out.is_empty() {
			out.push(',');
		}
		if start == end {
			out.push_str(&start.to_string());
		} else {
			out.push_str(&format!("{start}:{end}"));
		}
		at += 1;
	}
	out
}

/// Server text made safe to print: printable ASCII only, at most 200
/// characters.
pub(crate) fn sanitize(text: &[u8]) -> String {
	text.iter()
		.take(200)
		.map(|&b| {
			if (0x20..0x7f).contains(&b) {
				char::from(b)
			} else {
				'?'
			}
		})
		.collect()
}
