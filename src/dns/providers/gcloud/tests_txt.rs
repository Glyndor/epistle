//! TXT-specific gcloud tests: long values, joined character-strings, the
//! upsert-replaces and delete-removes-one-record contracts, and the
//! wire-form round-trip. Split from `gcloud_tests.rs` so neither file
//! crosses the line limit; the shared mock (`start_mock`, `Rrset`,
//! `provider_for`, `txt`) lives in `super::test_support`.

use super::test_support::*;
use super::*;

/// A TXT record longer than 255 bytes is one record made of several
/// character-strings (RFC 1035 §3.3.14). The wire form is one entry
/// of `rrdatas` carrying the quoted pieces joined with a single
/// space; resolvers concatenate the pieces back into one logical
/// value on read. Several entries in an RRset would be several TXT
/// records, which is what the previous attempt produced and what
/// every DKIM verifier rejects. The test uses a 400-byte value
/// (first 255 + last 145, two pieces) so the joined shape is
/// unambiguous and the per-piece boundary is exact.
#[tokio::test]
async fn txt_upsert_emits_long_value_as_one_rrdata_with_joined_pieces() {
	let (base, state) = start_mock(Vec::new()).await;
	let provider = provider_for(&base);
	let long_value: String = "a".repeat(400);
	provider
		.upsert("example.org", txt("s2._domainkey.example.org", &long_value))
		.await
		.expect("upsert");
	let body = state.lock().unwrap().changes.last().cloned().unwrap();
	let rrdatas = extract_rrdatas(&body);
	// One rrdatas entry carrying the joined pieces, never one per
	// piece: several pieces means several TXT records, which no
	// resolver stitches back into one DKIM key.
	assert_eq!(
		rrdatas.len(),
		1,
		"a long TXT must be ONE rrdatas entry, body: {body}"
	);
	// The joined shape: two quoted pieces, 255 + 145 bytes, with
	// a single space between them. The shape, not the bytes, is
	// what is asserted here, the full key value stays out of the
	// assertion message.
	let piece_lengths = rdata_piece_lengths(&rrdatas[0]);
	assert_eq!(
		piece_lengths,
		vec![255_usize, 145_usize],
		"expected joined pieces of 255 + 145 bytes, got {piece_lengths:?}"
	);
	// The resolvers concatenate the quoted pieces back into one
	// logical TXT value, which must equal what we sent.
	let assembled = assemble_rrdatas(&rrdatas);
	assert_eq!(
		assembled.len(),
		long_value.len(),
		"the joined pieces must reassemble into the original length"
	);
	assert_eq!(
		assembled, long_value,
		"the joined pieces must reassemble into the original bytes"
	);
}

/// A short TXT (≤255 bytes) keeps the existing single-chunk shape:
/// one quoted, escaped rdata. The chunking must not be applied to
/// values that already fit, otherwise the wire form changes for SPF
/// and DMARC and the deletion test would break.
#[tokio::test]
async fn txt_upsert_keeps_short_value_in_one_rrdata() {
	let (base, state) = start_mock(Vec::new()).await;
	let provider = provider_for(&base);
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	let body = state.lock().unwrap().changes.last().cloned().unwrap();
	let rrdatas = extract_rrdatas(&body);
	assert_eq!(
		rrdatas.len(),
		1,
		"short TXT must stay a single rdata, body: {body}"
	);
	assert_eq!(rrdatas[0], r#""v=DMARC1; p=none""#);
}

/// The per-piece backslash and quote escaping has to apply to the
/// piece, not to the joined value, so a value with `\"` and `\\`
/// mid-piece round-trips. The body must be one `rrdatas` entry with
/// two quoted pieces; the assembled value must equal what was sent.
/// The exact bytes are not echoed in the assertion message, only
/// the piece count, the per-piece ≤255 cap, and the round-trip length.
#[tokio::test]
async fn txt_upsert_long_value_escapes_per_piece() {
	let (base, state) = start_mock(Vec::new()).await;
	let provider = provider_for(&base);
	// 1 + 299 'a' + `\"` + 10 'c' = 312 bytes. Splits at 255 and
	// 57. The `\"` lands inside the first piece, not at a boundary,
	// so a per-piece escape is exercised rather than the boundary
	// joining.
	let mut value = String::from("a");
	value.push_str(&"a".repeat(299));
	value.push_str(r#"\""#);
	value.push_str(&"c".repeat(10));
	provider
		.upsert("example.org", txt("s2._domainkey.example.org", &value))
		.await
		.expect("upsert");
	let body = state.lock().unwrap().changes.last().cloned().unwrap();
	let rrdatas = extract_rrdatas(&body);
	assert_eq!(
		rrdatas.len(),
		1,
		"a long TXT must be ONE rrdatas entry, body: {body}"
	);
	let piece_lengths = rdata_piece_lengths(&rrdatas[0]);
	assert_eq!(
		piece_lengths.len(),
		2,
		"expected 2 joined pieces, got {piece_lengths:?}"
	);
	// Every piece must respect the 255-byte cap, regardless of
	// where the per-piece escapes fall. The wire form is longer
	// than the source by 2 bytes (one `\` and one `"` in the second
	// piece, each expanded by one escape byte), so the total
	// piece-bytes summed equals the source length plus the escape
	// insertions.
	assert!(
		piece_lengths.iter().all(|&l| l <= 255),
		"every joined piece must be ≤ 255 bytes, got {piece_lengths:?}"
	);
	let total: usize = piece_lengths.iter().sum();
	assert_eq!(
		total,
		value.len() + 2,
		"total piece bytes must equal source + per-piece escape insertions, got {total}"
	);
	let assembled = assemble_rrdatas(&rrdatas);
	assert_eq!(
		assembled.len(),
		value.len(),
		"joined pieces must reassemble into the original length"
	);
	assert_eq!(
		assembled, value,
		"per-piece escape must round-trip the value"
	);
}

/// Upsert of a new long TXT value, against a zone that already
/// carries an older long TXT value, must replace the record (one
/// `rrdatas` entry with the new joined form, no duplicate, no
/// leftover). Cloud DNS reads the live rrset and replaces it with a
/// single `deletions` + `additions` pair in one change request.
#[tokio::test]
async fn txt_upsert_replaces_existing_long_record_without_duplicating() {
	// Seed the live rrsets with the joined form of the OLD long
	// value (one rrdatas entry, two quoted pieces). The mock's
	// list_rrsets handler reads `live_rrsets`.
	let old = "a".repeat(400);
	let initial = vec![Rrset {
		name: "s2._domainkey.example.org.".into(),
		kind: "TXT".into(),
		ttl: 3600,
		rrdatas: vec![rrdatas_joined_form(&old)],
	}];
	let (base, state) = start_mock(initial).await;
	let provider = provider_for(&base);
	let new_value: String = "b".repeat(400);
	provider
		.upsert("example.org", txt("s2._domainkey.example.org", &new_value))
		.await
		.expect("upsert");
	let body = state.lock().unwrap().changes.last().cloned().unwrap();
	// The change must be a single replace: deletions carrying the
	// old rrdatas and additions carrying the new rrdatas, both
	// exactly one entry each (no duplicate, no leftover).
	assert!(body.contains("\"deletions\":[{"), "{body}");
	assert!(body.contains("\"additions\":[{"), "{body}");
	let additions = extract_additions_rrdatas(&body);
	assert_eq!(
		additions.len(),
		1,
		"additions must carry exactly one rrdatas, body: {body}"
	);
	let piece_lengths = rdata_piece_lengths(&additions[0]);
	assert_eq!(
		piece_lengths,
		vec![255_usize, 145_usize],
		"additions must carry the new joined pieces, got {piece_lengths:?}"
	);
	let s = state.lock().unwrap();
	let surviving = s
		.live_rrsets
		.iter()
		.find(|r| r.name == "s2._domainkey.example.org." && r.kind == "TXT")
		.expect("the surviving rrset is the new value");
	assert_eq!(
		surviving.rrdatas.len(),
		1,
		"after upsert the rrset must carry exactly one rrdatas"
	);
}

/// Delete with a long TXT value must remove the one record that
/// carries the joined form, and must leave any sibling rrdatas at
/// the same owner alone. The previous round's multi-chunk short-circuit
/// dropped the whole rrset, including siblings, because the joined
/// value would never match any individual rrdatas it had stored
/// (those were separate character-strings, not the joined form).
/// The new path builds the needle from the joined form on both the
/// write and the read sides, so the matching works against the same
/// shape Cloud DNS lists back.
#[tokio::test]
async fn txt_delete_with_long_value_removes_that_one_record() {
	// Seed the rrset with the long value (joined form, one rrdatas)
	// and a sibling ACME challenge (a separate rrdatas). The delete
	// must drop the long rrdatas and leave the sibling.
	let long_value: String = "a".repeat(400);
	let sibling = "token-bbbb";
	let initial = vec![Rrset {
		name: "s2._domainkey.example.org.".into(),
		kind: "TXT".into(),
		ttl: 3600,
		rrdatas: vec![rrdatas_joined_form(&long_value), format!("\"{sibling}\"")],
	}];
	let (base, state) = start_mock(initial).await;
	let provider = provider_for(&base);
	provider
		.delete("example.org", txt("s2._domainkey.example.org", &long_value))
		.await
		.expect("delete");
	let body = state.lock().unwrap().changes.last().cloned().unwrap();
	// The change replaces the rrset: `additions` carries the
	// surviving rrdatas (the sibling), `deletions` carries the
	// previous rrset (both rrdatas).
	let additions = extract_additions_rrdatas(&body);
	assert_eq!(
		additions.len(),
		1,
		"additions must carry exactly one rrdatas (the sibling), body: {body}"
	);
	assert_eq!(
		additions[0],
		format!("\"{sibling}\""),
		"the sibling must survive the delete, body: {body}"
	);
	let s = state.lock().unwrap();
	let surviving = s
		.live_rrsets
		.iter()
		.find(|r| r.name == "s2._domainkey.example.org." && r.kind == "TXT")
		.expect("the rrset is still in the zone with the sibling");
	assert_eq!(
		surviving.rrdatas,
		vec![format!("\"{sibling}\"")],
		"the long-value rrdatas must be gone, the sibling must remain"
	);
}

/// Pull the first `"rrdatas":[...]` array out of a Cloud DNS change
/// body and decode each element as a JSON string. The body is JSON
/// (the change request), so this avoids any hand-rolled parsing.
fn extract_rrdatas(body: &str) -> Vec<String> {
	let value: Value = serde_json::from_str(body).expect("change body is JSON");
	let additions = value
		.get("additions")
		.and_then(|a| a.as_array())
		.expect("additions");
	let rrset = additions.first().expect("an additions entry");
	let rrdatas = rrset
		.get("rrdatas")
		.and_then(|r| r.as_array())
		.expect("rrdatas");
	rrdatas
		.iter()
		.map(|v| v.as_str().expect("string rdata").to_string())
		.collect()
}

/// Mirror what a DNS resolver does on read: each rdata is a sequence
/// of one or more quoted character-strings; walk the pieces, drop the
/// surrounding double quotes on each, resolve the per-piece `\\` and
/// `\"` escapes, and concatenate in order. Works for the short-value
/// shape (one quoted string per rdata) and the long-value joined
/// shape (multiple quoted strings inside one rdata, separated by a
/// single space).
fn assemble_rrdatas(rrdatas: &[String]) -> String {
	let mut out = String::new();
	for rdata in rrdatas {
		let bytes = rdata.as_bytes();
		let mut i = 0;
		while i < bytes.len() {
			if bytes[i] == b'"' {
				let piece_start = i + 1;
				let mut piece_end = piece_start;
				while piece_end < bytes.len() {
					if bytes[piece_end] == b'\\' && piece_end + 1 < bytes.len() {
						piece_end += 2;
					} else if bytes[piece_end] == b'"' {
						break;
					} else {
						piece_end += 1;
					}
				}
				if piece_end >= bytes.len() {
					break;
				}
				let piece = &rdata[piece_start..piece_end];
				let mut chars = piece.chars();
				while let Some(c) = chars.next() {
					if c == '\\' {
						match chars.next() {
							Some('\\') => out.push('\\'),
							Some('"') => out.push('"'),
							Some(other) => {
								out.push('\\');
								out.push(other);
							}
							None => out.push('\\'),
						}
					} else {
						out.push(c);
					}
				}
				i = piece_end + 1;
			} else {
				i += 1;
			}
		}
	}
	out
}

/// Length of each quoted piece inside a joined Cloud DNS `rrdatas`
/// entry. The wire form is `"piece1" "piece2"`; the pieces are the
/// substrings between the surrounding double quotes, with the
/// per-piece backslash/quote escapes honored so `\"` is one escaped
/// quote (2 wire bytes), not a piece terminator. Returns the
/// wire-byte lengths, in order, so the assertions compare against
/// `vec![255, 145]` without printing the underlying bytes.
fn rdata_piece_lengths(rdata: &str) -> Vec<usize> {
	let bytes = rdata.as_bytes();
	let mut out = Vec::new();
	let mut i = 0;
	while i < bytes.len() {
		if bytes[i] == b'"' {
			let start = i + 1;
			let mut j = start;
			while j < bytes.len() {
				if bytes[j] == b'\\' && j + 1 < bytes.len() {
					j += 2;
				} else if bytes[j] == b'"' {
					break;
				} else {
					j += 1;
				}
			}
			if j >= bytes.len() {
				break;
			}
			out.push(j - start);
			i = j + 1;
		} else {
			i += 1;
		}
	}
	out
}

/// The wire form of a Cloud DNS `rrdatas` entry the production code
/// writes and reads back: each ≤255-octet character-string is
/// backslash/quote-escaped per piece, then wrapped in double quotes,
/// then the pieces are joined with single spaces. Used to seed the
/// mock's `live_rrsets` with the same shape the production code
/// writes, so the value-bearing delete's needle matches the listed
/// rdata.
fn rrdatas_joined_form(value: &str) -> String {
	let mut start = 0;
	let mut out = String::new();
	while start < value.len() {
		let mut end = (start + 255).min(value.len());
		while end < value.len() && !value.is_char_boundary(end) {
			end -= 1;
		}
		let piece = &value[start..end];
		let escaped = piece.replace('\\', "\\\\").replace('"', "\\\"");
		if !out.is_empty() {
			out.push(' ');
		}
		out.push('"');
		out.push_str(&escaped);
		out.push('"');
		start = end;
	}
	out
}

/// Pull the `"rrdatas":[...]` of the first entry in `additions` out
/// of a Cloud DNS change body. The body is JSON (the change request).
fn extract_additions_rrdatas(body: &str) -> Vec<String> {
	let value: Value = serde_json::from_str(body).expect("change body is JSON");
	let additions = value
		.get("additions")
		.and_then(|a| a.as_array())
		.expect("additions");
	let rrset = additions.first().expect("an additions entry");
	let rrdatas = rrset
		.get("rrdatas")
		.and_then(|r| r.as_array())
		.expect("rrdatas");
	rrdatas
		.iter()
		.map(|v| v.as_str().expect("string rdata").to_string())
		.collect()
}
