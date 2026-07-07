//! HTTP Basic authentication and the owner-only ACL.
//!
//! Every WebDAV request must carry HTTP Basic credentials that the directory
//! accepts ([`crate::directory_store::Directory::authenticate`]). The resolved
//! account name returned by the directory — not the login the client typed — is
//! what selects the on-disk tree, so an account can only ever reach its own
//! files: this is the ACL. A missing or bad credential is a `401` carrying a
//! `WWW-Authenticate: Basic` challenge; everything fails closed.

use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;

use crate::directory_store::DirectoryHandle;

/// The realm advertised in the `WWW-Authenticate` challenge.
pub const REALM: &str = "WebDAV";

/// Authenticate the request against the directory, returning the resolved
/// account name on success. Returns `None` for a missing, malformed, or
/// rejected credential — the caller turns that into a `401` challenge.
pub fn authenticate(headers: &HeaderMap, directory: &DirectoryHandle) -> Option<String> {
	let (login, password) = basic_credentials(headers)?;
	directory.current().authenticate(&login, &password)
}

/// Parse a `Authorization: Basic <base64(user:pass)>` header into its login and
/// password. Returns `None` if the scheme is not Basic, the base64 is invalid,
/// the decoded value is not UTF-8, or it has no `:` separator.
fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
	let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
	let encoded = value
		.strip_prefix("Basic ")
		.or_else(|| value.strip_prefix("basic "))?;
	let decoded = base64_decode(encoded.trim())?;
	let text = String::from_utf8(decoded).ok()?;
	let (login, password) = text.split_once(':')?;
	Some((login.to_string(), password.to_string()))
}

/// Decode standard (RFC 4648) base64 without padding-strictness, returning the
/// raw bytes or `None` on any invalid character or truncated group.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
	let mut bits: u32 = 0;
	let mut nbits = 0u32;
	let mut out = Vec::with_capacity(input.len() / 4 * 3);
	for byte in input.bytes() {
		let value = match byte {
			b'A'..=b'Z' => byte - b'A',
			b'a'..=b'z' => byte - b'a' + 26,
			b'0'..=b'9' => byte - b'0' + 52,
			b'+' => 62,
			b'/' => 63,
			b'=' => break,
			_ => return None,
		};
		bits = (bits << 6) | u32::from(value);
		nbits += 6;
		if nbits >= 8 {
			nbits -= 8;
			out.push((bits >> nbits) as u8);
		}
	}
	Some(out)
}

#[cfg(test)]
#[path = "auth_tests.rs"]
mod tests;
