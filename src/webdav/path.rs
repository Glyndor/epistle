//! Mapping a request URI path into an account's confined DAV tree.
//!
//! Every authenticated account owns exactly one subtree on disk:
//! `<data_dir>/accounts/<account>/dav`. A request path is resolved relative to
//! that root and is rejected (fail closed) if it could escape the root: any `..`
//! segment, an embedded NUL, or — after resolution — a path that is not a
//! descendant of the root. Beyond lexical confinement, every component between
//! the root and the target must also be a real directory (no symlink), so a
//! symlink planted by anyone with shell access into the user's tree cannot be
//! followed to an outside file. This is the storage half of the owner-only ACL:
//! an account can never name a file outside its own tree.

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

/// Confine an existing `target` (one already on disk) under `root` for a read
/// or delete: the canonical form of `target` (following every symlink) must
/// fall under the canonical form of `root`, and no component between `root`
/// and `target` may itself be a symlink. The final component must not be a
/// symlink either, a symlink at the leaf could resolve outside the account
/// even when `canonicalize` claimed it stayed inside.
///
/// Returns `true` when the target exists and is safely under the root,
/// `false` when a symlink at any position would let the request escape, or
/// when the path components fail their lexical checks. A missing target
/// returns `true` too, there is nothing to follow, so there is no escape
/// possible; the caller turns a missing-target GET into `404`.
pub fn confine_existing(target: &Path, root: &Path) -> bool {
	let Ok(canonical_root) = root.canonicalize() else {
		return true;
	};
	let Ok(canonical) = target.canonicalize() else {
		// The target does not exist on disk. Nothing to follow; the handler
		// will surface the missing file as `404` (or whatever is right for
		// the method). No symlink risk.
		return true;
	};
	if !canonical.starts_with(&canonical_root) {
		return false;
	}
	let rel = canonical.strip_prefix(&canonical_root).ok();
	let Some(rel) = rel else {
		return false;
	};
	let mut cur = canonical_root;
	for component in rel.components() {
		let Component::Normal(name) = component else {
			return false;
		};
		cur.push(name);
		let Ok(meta) = std::fs::symlink_metadata(&cur) else {
			return false;
		};
		if meta.file_type().is_symlink() {
			return false;
		}
	}
	true
}

/// Confine a not-yet-existing `target` (a PUT or MKCOL) under `root`: when the
/// parent directory exists, it must be a real directory, no component between
/// `root` and `parent` may be a symlink, and the canonical form of the parent
/// must fall under the canonical form of `root`. A missing parent is allowed:
/// the handler will surface it as `409 Conflict`; there is no symlink to
/// follow there. The final segment is allowed to be absent (the request
/// creates it); if it exists, it must be the right kind (regular file for
/// PUT, absent for MKCOL, caller's job).
///
/// Returns `true` on a safe write-create path, `false` only when an existing
/// parent lies under a symlink at some intermediate position, or escapes the
/// canonical root.
pub fn confine_parent_for_write(target: &Path, root: &Path) -> bool {
	let Ok(canonical_root) = root.canonicalize() else {
		return false;
	};
	let Some(parent) = target.parent() else {
		return false;
	};
	// A parent that does not exist on disk is not a symlink we can follow;
	// the handler will produce `409 Conflict` (RFC 4918 §9.7.1, a PUT to a
	// non-existent collection is a conflict). Allow it.
	let Ok(canonical_parent) = parent.canonicalize() else {
		return true;
	};
	if !canonical_parent.starts_with(&canonical_root) {
		return false;
	}
	let rel = canonical_parent.strip_prefix(&canonical_root).ok();
	let Some(rel) = rel else {
		return false;
	};
	let mut cur = canonical_root;
	for component in rel.components() {
		let Component::Normal(name) = component else {
			return false;
		};
		cur.push(name);
		let Ok(meta) = std::fs::symlink_metadata(&cur) else {
			return false;
		};
		if meta.file_type().is_symlink() {
			return false;
		}
		if !meta.is_dir() {
			return false;
		}
	}
	true
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
