//! The trace fields final delivery adds to the copy it stores.
//!
//! RFC 5321 section 4.4: the system that makes final delivery inserts
//! `Return-Path` with the reverse-path of the transaction at the top of the
//! message, `<>` for the null sender. A relay must not add one, so whatever
//! `Return-Path` a message arrives with was written by someone else and is
//! not trusted: it is removed before ours goes on, and every stored copy
//! carries exactly one.

use crate::smtp::trace::strip_headers;

/// The copy of `data` that lands in a mailbox for a message whose envelope
/// sender was `reverse_path`.
pub(super) fn final_copy(reverse_path: &str, data: &[u8]) -> Vec<u8> {
	// The reverse-path was parsed from the envelope; a line break in it
	// would still start a field of its own, so none survives.
	let reverse_path: String = reverse_path
		.chars()
		.filter(|c| !matches!(c, '\r' | '\n'))
		.collect();
	let mut copy = format!("Return-Path: <{reverse_path}>\r\n").into_bytes();
	copy.extend_from_slice(&strip_headers(data, &["return-path"]));
	copy
}
