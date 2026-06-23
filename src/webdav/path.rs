//! Mapping a request URI path into an account's confined DAV tree.
//!
//! Every authenticated account owns exactly one subtree on disk:
//! `<data_dir>/accounts/<account>/dav`. A request path is resolved relative to
//! that root and is rejected (fail closed) if it could escape the root: any `..`
//! segment, an embedded NUL, or — after resolution — a path that is not a
//! descendant of the root. This is the storage half of the owner-only ACL: an
//! account can never name a file outside its own tree.

use std::path::{Component, Path, PathBuf};

/// The per-account DAV root: `<data_dir>/accounts/<account>/dav`.
///
/// The account name is taken verbatim from [`crate::smtp::directory`] (the
/// authenticated, resolved account), so it is not attacker-controlled; we still
/// reject a name containing a path separator or `..` as defence in depth.
pub fn account_root(data_dir: &Path, account: &str) -> Option<PathBuf> {
	if account.is_empty()
		|| account.contains('/')
		|| account.contains('\\')
		|| account.contains('\0')
		|| account == ".."
		|| account == "."
	{
		return None;
	}
	Some(data_dir.join("accounts").join(account).join("dav"))
}

/// Resolve a request URI path (e.g. `/dir/file.txt`) into an absolute on-disk
/// path inside `root`, or `None` if it would escape the root.
///
/// The path is decoded, split on `/`, and walked component by component:
/// `.` is skipped, a leading/empty segment is skipped, and `..` is rejected
/// outright (we never pop, so there is no way to climb above the root). A NUL
/// byte anywhere is rejected. The result is always a descendant of `root`.
pub fn resolve(root: &Path, uri_path: &str) -> Option<PathBuf> {
	let decoded = percent_decode(uri_path)?;
	if decoded.contains('\0') {
		return None;
	}
	let mut out = root.to_path_buf();
	for segment in decoded.split('/') {
		match segment {
			"" | "." => continue,
			".." => return None,
			other => {
				// A decoded segment must not itself contain a separator or a
				// platform path component that is not plain (drive, root, ..).
				if other.contains('\\') {
					return None;
				}
				let component = Path::new(other);
				let mut comps = component.components();
				match (comps.next(), comps.next()) {
					(Some(Component::Normal(name)), None) => out.push(name),
					_ => return None,
				}
			}
		}
	}
	// Final guard: the resolved path must still be under the root. This also
	// catches any component the loop above failed to neutralise.
	if !out.starts_with(root) {
		return None;
	}
	Some(out)
}

/// Decode `%XX` percent-escapes in a URI path into a UTF-8 string, or `None`
/// for a malformed escape or non-UTF-8 result. `+` is left literal (it is a
/// query convention, not a path one).
fn percent_decode(input: &str) -> Option<String> {
	let bytes = input.as_bytes();
	let mut out = Vec::with_capacity(bytes.len());
	let mut i = 0;
	while i < bytes.len() {
		match bytes[i] {
			b'%' => {
				let hi = hex_val(*bytes.get(i + 1)?)?;
				let lo = hex_val(*bytes.get(i + 2)?)?;
				out.push((hi << 4) | lo);
				i += 3;
			}
			byte => {
				out.push(byte);
				i += 1;
			}
		}
	}
	String::from_utf8(out).ok()
}

/// Hex digit value of an ASCII byte, or `None` if it is not a hex digit.
fn hex_val(byte: u8) -> Option<u8> {
	match byte {
		b'0'..=b'9' => Some(byte - b'0'),
		b'a'..=b'f' => Some(byte - b'a' + 10),
		b'A'..=b'F' => Some(byte - b'A' + 10),
		_ => None,
	}
}

#[cfg(test)]
#[path = "path_tests.rs"]
mod tests;
