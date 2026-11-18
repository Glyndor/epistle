//! Drop or deduplicate header fields by name, or by a reserved namespace.

use crate::smtp::inbound_headers::{name_matches, name_starts_with};

use super::{rewrite_header_block, rewrite_header_block_in_place, same_name};

/// `data` without any header field whose name is one of `names` (compared as a
/// reader after us reads a name, `same_name` in this module), folded
/// continuation lines included. The body and every other field are kept byte
/// for byte.
pub fn strip_headers(data: &[u8], names: &[&str]) -> Vec<u8> {
	rewrite_header_block(data, |name| !named(name, names))
}

/// `data` rewritten to keep only the first field of each name in `names`
/// (compared as a reader after us reads a name, `same_name` in this module),
/// folded continuation lines included. Two fields of one name are two claims
/// about the same header, and nothing in RFC 2369 or RFC 8058 says which of
/// them a receiver acts on. Several URLs inside a single field are a different
/// thing and stay: one field may carry up to four of them, and they are one
/// claim. The body and every other field are kept byte for byte.
pub fn keep_first_of_each_in_place(data: &mut Vec<u8>, names: &[&str]) {
	let mut seen = vec![false; names.len()];
	rewrite_header_block_in_place(data, |name| {
		let Some(index) = names
			.iter()
			.position(|wanted| named(name, std::slice::from_ref(wanted)))
		else {
			return true;
		};
		let first = !seen[index];
		seen[index] = true;
		first
	});
}

/// Whether `name` is one of `names`, the way a reader after us reads a name.
fn named(name: &[u8], names: &[&str]) -> bool {
	names
		.iter()
		.any(|wanted| same_name(name, wanted.as_bytes()))
}

/// `data` without any header field in the namespace `name` (compared
/// case-insensitively), folded continuation lines included. The body and
/// every other field are kept byte for byte. Used to reserve a namespace
/// (`X-Epistle`): one field cannot be named in a list that a future field
/// would have to be added to.
///
/// The namespace is the exact field name and that name followed by a
/// hyphen, not a text prefix: `X-Epistle` and `X-Epistle-Future` are ours,
/// `X-Epistlefoo` belongs to whoever sent it.
pub fn strip_headers_with_namespace(data: &[u8], name: &str) -> Vec<u8> {
	rewrite_header_block(data, |field| !in_namespace(field, name.as_bytes()))
}

/// Whether the field name `field` is `namespace` itself or a name inside it,
/// the hyphen included, read the way a downstream reader reads it: case
/// folded, with the same tolerance for whitespace and separators inside the
/// name that the inbound strip applies, so `X-Epistle-` alone and a spaced
/// spelling are covered too. `X-Epistlefoo` is a different name and stays.
fn in_namespace(field: &[u8], namespace: &[u8]) -> bool {
	let mut dashed = namespace.to_vec();
	dashed.push(b'-');
	name_matches(field, namespace) || name_starts_with(field, &dashed)
}

/// In-place header strip: rewrite `data` in place to remove every
/// header field whose name is one of `names`, folded continuation
/// lines included.
pub fn strip_headers_in_place(data: &mut Vec<u8>, names: &[&str]) {
	rewrite_header_block_in_place(data, |name| !named(name, names))
}
