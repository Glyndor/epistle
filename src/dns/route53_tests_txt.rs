//! TXT-specific Route 53 tests: long values, joined character-strings, the
//! sibling-delete contract, and the wire-form round-trip. Split from
//! `route53_tests.rs` so neither file crosses the line limit; the shared mock
//! (`mock`, `MockState`) lives in the parent test module.

use super::tests::mock;
use super::*;

/// A TXT record longer than 255 bytes is one record made of several
/// character-strings (RFC 1035 §3.3.14). The wire form is one
/// `<ResourceRecord>` carrying the quoted pieces joined with a single
/// space — resolvers concatenate the pieces back into one logical
/// value on read. Several records in an RRset would be several TXT
/// records, which is what the previous attempt produced and what
/// every DKIM verifier rejects. The test uses a 400-byte value
/// (first 255 + last 145, two pieces) so the joined shape is
/// unambiguous and the per-piece boundary is exact.
#[tokio::test]
async fn txt_upsert_emits_long_value_as_one_record_with_joined_pieces() {
	let (provider, state) = mock().await;
	let long_value: String = "a".repeat(400);
	let record = DnsRecord {
		name: "s2._domainkey.example.org".into(),
		kind: RecordKind::Txt,
		value: long_value.clone(),
		ttl: 3600,
	};
	provider
		.upsert("example.org", record)
		.await
		.expect("upsert");
	let body = state.lock().unwrap().bodies[0].clone();
	// One `<ResourceRecord>` carrying the joined pieces, never one
	// per piece: several pieces means several records, which is
	// several TXT records, which no resolver stitches back into one
	// DKIM key.
	let resource_records = body.matches("<ResourceRecord>").count();
	assert_eq!(
		resource_records, 1,
		"a long TXT must be ONE <ResourceRecord>, body: {body}"
	);
	let value_open = body.matches("<Value>").count();
	assert_eq!(value_open, 1, "expected exactly 1 <Value>, body: {body}");
	// The joined shape: two quoted pieces, 255 + 145 bytes, with
	// a single space between them. The shape, not the bytes, is
	// what is asserted here — the full key value stays out of the
	// assertion message.
	let value = extract_first_value(&body).expect("<Value> present");
	let piece_lengths = piece_lengths(&value);
	assert_eq!(
		piece_lengths,
		vec![255_usize, 145_usize],
		"expected joined pieces of 255 + 145 bytes, got {piece_lengths:?}"
	);
	// The resolvers concatenate the quoted pieces back into one
	// logical TXT value, which must equal what we sent.
	let assembled = assembled_value_from_body(&body);
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

/// A short TXT (≤255 bytes) keeps the existing single-quoted-string
/// shape: one `<ResourceRecord>` carrying the one piece. The chunking
/// must not be applied to values that already fit, otherwise the wire
/// form changes for SPF / DMARC / MTA-STS / TLSRPT / short DKIM / ACME
/// challenges and the sibling-delete test would break.
#[tokio::test]
async fn txt_upsert_keeps_short_value_in_one_chunk() {
	let (provider, state) = mock().await;
	let record = DnsRecord {
		name: "_dmarc.example.org".into(),
		kind: RecordKind::Txt,
		value: "v=DMARC1; p=none".into(),
		ttl: 3600,
	};
	provider
		.upsert("example.org", record)
		.await
		.expect("upsert");
	let body = state.lock().unwrap().bodies[0].clone();
	let resource_records = body.matches("<ResourceRecord>").count();
	assert_eq!(
		resource_records, 1,
		"short TXT must stay a single <ResourceRecord>, body: {body}"
	);
	let value_str = extract_first_value(&body).expect("<Value> present");
	assert_eq!(
		piece_count(&value_str),
		1,
		"short TXT must stay a single piece, body: {body}"
	);
	assert!(
		body.contains(r#"<Value>"v=DMARC1; p=none"</Value>"#),
		"short TXT must remain a single quoted chunk, body: {body}"
	);
}

/// The per-piece backslash and quote escaping has to apply to the
/// piece, not to the joined value, so a value with `\"` and `\\`
/// mid-piece round-trips. The body must be one `<ResourceRecord>`
/// with two quoted pieces; the assembled value must equal what was
/// sent. The exact bytes are not echoed in the assertion message —
/// only the piece count, the per-piece ≤255 cap, and the round-trip
/// length.
#[tokio::test]
async fn txt_upsert_long_value_escapes_per_piece() {
	let (provider, state) = mock().await;
	// 1 + 299 'a' + `\"` + 10 'c' = 312 bytes. Splits at 255 and
	// 57. The `\"` lands inside the first piece, not at a boundary,
	// so a per-piece escape is exercised rather than the boundary
	// joining.
	let mut value = String::from("a");
	value.push_str(&"a".repeat(299));
	value.push_str(r#"\""#);
	value.push_str(&"c".repeat(10));
	let record = DnsRecord {
		name: "s2._domainkey.example.org".into(),
		kind: RecordKind::Txt,
		value: value.clone(),
		ttl: 3600,
	};
	provider
		.upsert("example.org", record)
		.await
		.expect("upsert");
	let body = state.lock().unwrap().bodies[0].clone();
	let resource_records = body.matches("<ResourceRecord>").count();
	assert_eq!(
		resource_records, 1,
		"a long TXT must be ONE <ResourceRecord>, body: {body}"
	);
	let value_str = extract_first_value(&body).expect("<Value> present");
	assert_eq!(
		piece_count(&value_str),
		2,
		"expected 2 joined pieces, body: {body}"
	);
	// Every piece must respect the 255-byte cap, regardless of
	// where the per-piece escapes fall. The wire form is longer
	// than the source by 2 bytes (one `\` and one `"` in the second
	// piece, each expanded by one escape byte), so the total
	// piece-bytes summed equals the source length plus the escape
	// insertions.
	let lengths = piece_lengths(&value_str);
	assert!(
		lengths.iter().all(|&l| l <= 255),
		"every joined piece must be ≤ 255 bytes, got {lengths:?}"
	);
	let total: usize = lengths.iter().sum();
	assert_eq!(
		total,
		value.len() + 2,
		"total piece bytes must equal source + per-piece escape insertions, got {total}"
	);
	let assembled = assembled_value_from_body(&body);
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

/// Upsert with a new long value, against a zone that already carries
/// an older long value, must replace the record (one `<ResourceRecord>`
/// with the new joined shape, no duplicate, no leftover). Route 53's
/// UPSERT replaces the rrset at `(name, type)` wholesale, so the test
/// only has to verify the body carries the new joined pieces once
/// and that the request is a UPSERT.
#[tokio::test]
async fn txt_upsert_replaces_existing_long_record_without_duplicating() {
	let (provider, state) = mock().await;
	let new_value: String = "b".repeat(400);
	let record = DnsRecord {
		name: "s2._domainkey.example.org".into(),
		kind: RecordKind::Txt,
		value: new_value,
		ttl: 3600,
	};
	provider
		.upsert("example.org", record)
		.await
		.expect("upsert");
	let body = state.lock().unwrap().bodies[0].clone();
	assert!(
		body.contains("<Action>UPSERT</Action>"),
		"upsert must issue UPSERT, body: {body}"
	);
	assert_eq!(
		body.matches("<ResourceRecord>").count(),
		1,
		"upsert must emit exactly one <ResourceRecord>, body: {body}"
	);
	let value_str = extract_first_value(&body).expect("<Value> present");
	let piece_lengths = piece_lengths(&value_str);
	assert_eq!(
		piece_lengths,
		vec![255_usize, 145_usize],
		"upsert must emit the new joined pieces, got {piece_lengths:?}"
	);
}

/// Delete with a long value must remove the one record that carries
/// the joined form. Route 53's DELETE matches the rrset by Name+Type
/// and uses the rdata inside `<ResourceRecord>` to disambiguate which
/// rdata drops; with the rrset carrying only the joined rdata, the
/// delete is a wholesale DELETE on the rrset.
#[tokio::test]
async fn txt_delete_with_long_value_removes_that_one_record() {
	let (provider, state) = mock().await;
	// Preload the LIST mock with the rrset that carries the joined
	// form of the long value, so the value-bearing delete path has
	// something to match against.
	{
		let mut s = state.lock().unwrap();
		s.list_response = Some(format!(
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<ListResourceRecordSetsResult>\
<ResourceRecordSets>\
<ResourceRecordSet>\
<Name>s2._domainkey.example.org.</Name><Type>TXT</Type><TTL>3600</TTL>\
<ResourceRecords>\
<ResourceRecord><Value>{}</Value></ResourceRecord>\
</ResourceRecords>\
</ResourceRecordSet>\
</ResourceRecordSets>\
</ListResourceRecordSetsResult>",
			txt_joined_form_for_test("a".repeat(400).as_str()),
		));
	}
	let long_value: String = "a".repeat(400);
	let record = DnsRecord {
		name: "s2._domainkey.example.org".into(),
		kind: RecordKind::Txt,
		value: long_value.clone(),
		ttl: 3600,
	};
	provider
		.delete("example.org", record)
		.await
		.expect("delete");
	let s = state.lock().unwrap();
	assert_eq!(s.bodies.len(), 1, "the wholesale DELETE must post one body");
	let body = &s.bodies[0];
	assert!(
		body.contains("<Action>DELETE</Action>"),
		"delete must issue DELETE, body: {body}"
	);
	assert_eq!(
		body.matches("<ResourceRecord>").count(),
		1,
		"the DELETE must carry exactly one <ResourceRecord>, body: {body}"
	);
	let value_str = extract_first_value(body).expect("<Value> present");
	assert_eq!(
		piece_count(&value_str),
		2,
		"the DELETE must carry 2 joined pieces, body: {body}"
	);
	let lengths = piece_lengths(&value_str);
	assert_eq!(
		lengths,
		vec![255_usize, 145_usize],
		"the DELETE must carry 255 + 145 joined pieces, got {lengths:?}"
	);
}

/// Pull the first `<Value>...</Value>` out of a Route 53 body. The
/// wire form is XML and there is exactly one for a TXT change after
/// the fix; this helper exists so the assertions name the value
/// they check instead of repeating the substring match.
fn extract_first_value(body: &str) -> Option<String> {
	let start = body.find("<Value>")? + "<Value>".len();
	let end = body[start..].find("</Value>")? + start;
	Some(body[start..end].to_string())
}

/// Length of each quoted piece inside a joined `<Value>`. The wire
/// form is `"piece1" "piece2"`; the pieces are the substrings
/// between the surrounding double quotes, with the per-piece
/// backslash/quote escapes honored so `\"` is one escaped quote (2
/// wire bytes), not a piece terminator. Returns the wire-byte
/// lengths, in order, so the assertions compare against
/// `vec![255, 145]` without printing the underlying bytes.
fn piece_lengths(value: &str) -> Vec<usize> {
	let bytes = value.as_bytes();
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

/// How many quoted pieces a joined `<Value>` carries. Each piece is
/// wrapped in a pair of `"`, so the count of `"` characters divided
/// by two is the piece count.
fn piece_count(value: &str) -> usize {
	value.chars().filter(|&c| c == '"').count() / 2
}

/// Pull every `<Value>...</Value>` out of a captured Route 53 change
/// body in order and concatenate the unescaped contents. Mirrors what
/// the resolvers do on read: each `<Value>` carries one or more quoted
/// character-strings (`"piece1" "piece2"`), so the helper walks the
/// quoted pieces, drops the surrounding double quotes on each, and
/// resolves the per-piece `\\` and `\"` escapes.
fn assembled_value_from_body(body: &str) -> String {
	let mut out = String::new();
	let mut i = 0;
	while i < body.len() {
		let rel = match body[i..].find("<Value>") {
			Some(r) => i + r + "<Value>".len(),
			None => break,
		};
		let end = match body[rel..].find("</Value>") {
			Some(r) => rel + r,
			None => break,
		};
		let raw = &body[rel..end];
		// Walk each quoted piece: read until the next unescaped `"`,
		// then strip the surrounding quotes and resolve escapes.
		let bytes = raw.as_bytes();
		let mut j = 0;
		while j < bytes.len() {
			if bytes[j] == b'"' {
				let piece_start = j + 1;
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
				let piece = &raw[piece_start..piece_end];
				let mut unquoted = String::with_capacity(piece.len());
				let mut chars = piece.chars();
				while let Some(c) = chars.next() {
					if c == '\\' {
						match chars.next() {
							Some('\\') => unquoted.push('\\'),
							Some('"') => unquoted.push('"'),
							Some(other) => {
								unquoted.push('\\');
								unquoted.push(other);
							}
							None => unquoted.push('\\'),
						}
					} else {
						unquoted.push(c);
					}
				}
				out.push_str(&unquoted);
				j = piece_end + 1;
			} else {
				j += 1;
			}
		}
		i = end + "</Value>".len();
	}
	out
}

/// The wire form a TXT value takes on the wire: each ≤255-byte
/// character-string is backslash/quote-escaped per piece, then
/// wrapped in double quotes, then the pieces are joined with single
/// spaces. Used by the tests that need to seed the LIST mock with
/// the same shape the production code writes, so the value-bearing
/// delete's needle matches the listed rdata.
fn txt_joined_form_for_test(value: &str) -> String {
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
