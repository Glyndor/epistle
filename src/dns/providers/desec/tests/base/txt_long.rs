use super::*;

/// A TXT record longer than 255 bytes is one record made of several
/// character-strings (RFC 1035 §3.3.14). The wire form is one entry
/// of `records` carrying the quoted pieces joined with a single
/// space; resolvers concatenate the pieces back into one logical
/// value on read. Several entries would be several TXT records,
/// which is what the previous attempt produced and what every DKIM
/// verifier rejects. The test uses a 400-byte value (first 255 +
/// last 145, two pieces) so the joined shape is unambiguous and the
/// per-piece boundary is exact.
#[tokio::test]
async fn txt_upsert_emits_long_value_as_one_record_with_joined_pieces() {
	let (provider, state) = mock(serde_json::json!([])).await;
	let long_value: String = "a".repeat(400);
	provider
		.upsert("example.org", txt("s2._domainkey.example.org", &long_value))
		.await
		.expect("upsert");
	let body = state.lock().unwrap().puts[0].clone();
	let records = extract_records(&body);
	// One `records` entry carrying the joined pieces, never one
	// per piece: several pieces means several TXT records, which
	// no resolver stitches back into one DKIM key.
	assert_eq!(
		records.len(),
		1,
		"a long TXT must be ONE records entry, body: {body}"
	);
	// The joined shape: two quoted pieces, 255 + 145 bytes, with
	// a single space between them. The shape, not the bytes, is
	// what is asserted here, the full key value stays out of the
	// assertion message.
	let piece_lengths = record_piece_lengths(&records[0]);
	assert_eq!(
		piece_lengths,
		vec![255_usize, 145_usize],
		"expected joined pieces of 255 + 145 bytes, got {piece_lengths:?}"
	);
	// The resolvers concatenate the quoted pieces back into one
	// logical TXT value, which must equal what we sent.
	let assembled = assemble_records(&records);
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
/// one quoted, escaped entry. The chunking must not apply to values
/// that already fit, otherwise the wire form changes for SPF, DMARC,
/// and ACME challenges and the deletion test would break.
#[tokio::test]
async fn txt_upsert_keeps_short_value_in_one_record() {
	let (provider, state) = mock(serde_json::json!([])).await;
	provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");
	let body = state.lock().unwrap().puts[0].clone();
	let records = extract_records(&body);
	assert_eq!(
		records.len(),
		1,
		"short TXT must stay a single record, body: {body}"
	);
	assert_eq!(records[0], r#""v=DMARC1; p=none""#);
}

/// The per-piece backslash and quote escaping has to apply to the
/// piece, not to the joined value, so a value with `\"` and `\\`
/// mid-piece round-trips. The body must be one `records` entry with
/// two quoted pieces; the assembled value must equal what was sent.
/// The exact bytes are not echoed in the assertion message, only
/// the piece count, the per-piece ≤255 cap, and the round-trip length.
#[tokio::test]
async fn txt_upsert_long_value_escapes_per_piece() {
	let (provider, state) = mock(serde_json::json!([])).await;
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
	let body = state.lock().unwrap().puts[0].clone();
	let records = extract_records(&body);
	assert_eq!(
		records.len(),
		1,
		"a long TXT must be ONE records entry, body: {body}"
	);
	let piece_lengths = record_piece_lengths(&records[0]);
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
	let assembled = assemble_records(&records);
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
/// `records` entry with the new joined form, no duplicate, no
/// leftover). deSEC's bulk PUT replaces the rrset, so the change
/// carries the new entries only.
#[tokio::test]
async fn txt_upsert_replaces_existing_long_record_without_duplicating() {
	// Both values carry the DKIM tag, so the new one replaces the old
	// one under the upsert contract; each is 400 octets.
	let old = format!("v=DKIM1; p={}", "a".repeat(389));
	let rrsets = serde_json::json!([{
		"subname": "s2._domainkey",
		"type": "TXT",
		"ttl": 3600,
		"records": [records_joined_form(&old)],
	}]);
	let (provider, state) = mock(rrsets).await;
	let new_value = format!("v=DKIM1; p={}", "b".repeat(389));
	provider
		.upsert("example.org", txt("s2._domainkey.example.org", &new_value))
		.await
		.expect("upsert");
	let body = state.lock().unwrap().puts[0].clone();
	let records = extract_records(&body);
	assert_eq!(
		records.len(),
		1,
		"upsert must carry exactly one records entry (no duplicate), body: {body}"
	);
	let piece_lengths = record_piece_lengths(&records[0]);
	assert_eq!(
		piece_lengths,
		vec![255_usize, 145_usize],
		"upsert must emit the new joined pieces, got {piece_lengths:?}"
	);
}

/// Delete with a long TXT value must remove the one record that
/// carries the joined form, and must leave any sibling record at
/// the same owner alone. The previous round's multi-chunk short-circuit
/// dropped the whole rrset, including siblings, because the joined
/// value would never match any individual record it had stored.
/// The new path builds the needle from the joined form on both the
/// write and the read sides, so the matching works against the same
/// shape deSEC lists back.
#[tokio::test]
async fn txt_delete_with_long_value_removes_that_one_record() {
	let long_value: String = "a".repeat(400);
	let sibling = "token-bbbb";
	let rrsets = serde_json::json!([{
		"subname": "s2._domainkey",
		"type": "TXT",
		"ttl": 3600,
		"records": [records_joined_form(&long_value), format!("\"{sibling}\"")],
	}]);
	let (provider, state) = mock(rrsets).await;
	provider
		.delete("example.org", txt("s2._domainkey.example.org", &long_value))
		.await
		.expect("delete");
	let body = state.lock().unwrap().puts[0].clone();
	let records = extract_records(&body);
	// The bulk PUT replaces the rrset with the surviving record
	// (the sibling). The long-value joined form is dropped.
	assert_eq!(
		records.len(),
		1,
		"the delete must leave exactly one record (the sibling), body: {body}"
	);
	assert_eq!(
		records[0],
		format!("\"{sibling}\""),
		"the sibling must survive, body: {body}"
	);
}
