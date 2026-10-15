//! Test inputs for the attachment inspection, built from byte prefixes.
//! Nothing here is, or contains, a working program: an "executable" is the
//! two-byte `MZ` header followed by padding. That is all the inspection
//! reads, so it is all the tests need.

use base64::Engine as _;

/// A PE header prefix and nothing that runs.
pub fn pe() -> Vec<u8> {
	let mut bytes = b"MZ\x90\x00\x03\x00\x00\x00".to_vec();
	bytes.resize(256, 0);
	bytes
}

/// A PDF header and a trailer.
pub fn pdf() -> Vec<u8> {
	b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n".to_vec()
}

/// One part of a test message.
pub struct Part<'a> {
	/// Raw header lines, without the final blank line.
	pub headers: &'a str,
	/// Content, base64-encoded into the part.
	pub content: &'a [u8],
}

/// An attachment part with a `filename` and a declared type.
pub fn attachment<'a>(headers: &'a str, content: &'a [u8]) -> Part<'a> {
	Part { headers, content }
}

/// A `multipart/mixed` message with a text body and `parts`, each
/// base64-encoded.
pub fn message(parts: &[Part<'_>]) -> Vec<u8> {
	let mut out = String::from(
		"From: a@example.org\r\nTo: b@example.net\r\nSubject: t\r\nMIME-Version: 1.0\r\n\
		 Content-Type: multipart/mixed; boundary=\"outer\"\r\n\r\npreamble\r\n\
		 --outer\r\nContent-Type: text/plain\r\n\r\nhello\r\n",
	);
	for part in parts {
		out.push_str("--outer\r\n");
		out.push_str(part.headers);
		out.push_str("\r\nContent-Transfer-Encoding: base64\r\n\r\n");
		let encoded = base64::engine::general_purpose::STANDARD.encode(part.content);
		for chunk in encoded.as_bytes().chunks(76) {
			out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
			out.push_str("\r\n");
		}
	}
	out.push_str("--outer--\r\n");
	out.into_bytes()
}
