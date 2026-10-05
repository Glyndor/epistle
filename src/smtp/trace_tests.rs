//! Tests for the trace-header helpers in [`super`]: the `Received:` hop
//! counter, the protocol keyword mapping, the SPF-domain resolution, and
//! `ensure_submission_headers` (the `Message-ID` / `Date` stamper for
//! authenticated submission).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::*;

fn at(epoch_secs: u64) -> SystemTime {
	UNIX_EPOCH + Duration::from_secs(epoch_secs)
}

#[test]
fn counts_received_headers_in_the_block_only() {
	let data = b"Received: from a\r\nReceived: from b\r\n\tby folded\r\n\
Subject: hi\r\n\r\nReceived: not a header in the body\r\n";
	// Two Received headers; the folded continuation and the body line
	// are not counted.
	assert_eq!(received_hop_count(data), 2);
}

#[test]
fn counts_zero_when_no_received_headers() {
	assert_eq!(received_hop_count(b"From: a@b\r\n\r\nbody\r\n"), 0);
}

#[test]
fn received_protocol_follows_rfc3848() {
	// HELO is plain SMTP regardless of TLS or auth.
	assert_eq!(received_protocol(false, false, false), "SMTP");
	assert_eq!(received_protocol(false, true, true), "SMTP");
	// EHLO gains S over TLS and A once authenticated.
	assert_eq!(received_protocol(true, false, false), "ESMTP");
	assert_eq!(received_protocol(true, true, false), "ESMTPS");
	assert_eq!(received_protocol(true, false, true), "ESMTPA");
	assert_eq!(received_protocol(true, true, true), "ESMTPSA");
}

#[test]
fn spf_domain_prefers_mail_from_then_helo() {
	assert_eq!(
		spf_domain("a@Example.ORG", Some("helo.example")),
		Some("example.org".to_string())
	);
	assert_eq!(
		spf_domain("", Some("helo.example")),
		Some("helo.example".to_string())
	);
	assert_eq!(spf_domain("", None), None);
}

/// Both `Message-ID` and `Date` are absent from a minimal submission: the
/// stamper writes both, the `Message-ID` is a UUIDv7 under `domain`, and
/// the `Date` parses as RFC 5322. The two new lines land at the very top
/// of the header block, ahead of every client-supplied header.
#[test]
fn adds_message_id_and_date_when_both_are_missing() {
	let data =
		b"From: alice@example.org\r\nTo: bob@elsewhere.example\r\nSubject: hi\r\n\r\nbody\r\n";
	let stamped = ensure_submission_headers(data, "example.org", at(1_780_662_896));
	let text = std::str::from_utf8(&stamped).expect("ascii");
	// Message-ID comes first, Date second, both ahead of the client headers.
	let message_id_idx = text.find("Message-ID: <").expect("message-id line");
	let date_idx = text.find("Date: ").expect("date line");
	let from_idx = text.find("From: ").expect("from line");
	assert!(message_id_idx < date_idx, "Message-ID before Date: {text}");
	assert!(date_idx < from_idx, "Date before From: {text}");
	// The Message-ID is shaped `<uuidv7@domain>`.
	let message_id_line = text
		.lines()
		.find(|line| line.starts_with("Message-ID:"))
		.expect("message-id line");
	let angle = message_id_line
		.find('<')
		.zip(message_id_line.find('>'))
		.expect("angle brackets");
	let id_inner = &message_id_line[angle.0 + 1..angle.1];
	let (local, domain) = id_inner.split_once('@').expect("local@domain");
	assert_eq!(domain, "example.org", "domain part of the minted id");
	let parsed = uuid::Uuid::parse_str(local).expect("local is a uuidv7");
	assert_eq!(
		parsed.get_version(),
		Some(uuid::Version::SortRand),
		"minted id must be uuidv7, got {parsed}"
	);
	// Date parses as RFC 5322: `Day, DD Mon YYYY HH:MM:SS +0000` (UTC).
	let date_line = text
		.lines()
		.find(|line| line.starts_with("Date: "))
		.expect("date line");
	let date_value = date_line.trim_start_matches("Date: ").trim();
	let parsed_date = chrono_parse(date_value);
	assert!(
		parsed_date,
		"Date must parse as RFC 5322, got {date_value:?}"
	);
	// The body and the client's own header lines remain intact.
	assert!(text.contains("From: alice@example.org"));
	assert!(text.contains("Subject: hi"));
	assert!(text.ends_with("body\r\n"));
}

/// Already-present `Message-ID` and `Date` are left alone: the output is
/// byte-identical to the input. The control test for the "we never
/// override the client" half of the contract.
#[test]
fn keeps_an_existing_message_id_and_date_untouched() {
	let data = b"Message-ID: <client@example.org>\r\nDate: Mon, 01 Jan 2024 12:00:00 +0000\r\nSubject: hi\r\n\r\nbody\r\n";
	let stamped = ensure_submission_headers(data, "example.org", at(1_780_662_896));
	assert_eq!(stamped, data);
}

/// Field-name matching is case-insensitive and ignores any same-named line
/// that lives in the body, after the blank line. The lowercase `message-id:`
/// in the header block is recognised; the uppercase one in the body is not.
#[test]
fn matches_header_names_case_insensitively_and_ignores_the_body() {
	let data = b"message-id: <client@example.org>\r\nSubject: hi\r\n\r\n\
Message-ID: not a header in the body\r\n";
	let stamped = ensure_submission_headers(data, "example.org", at(1_780_662_896));
	let text = std::str::from_utf8(&stamped).expect("ascii");
	// The stamper must not add a fresh Message-ID: the lowercase form in
	// the headers was recognised, so the only Message-ID lines in the
	// output are the client's (in the headers, lowercase) and the body's
	// own (uppercase, after the blank line). The first non-empty line of
	// the result is the stamper's Date, proving no Message-ID was
	// prepended.
	assert!(
		text.starts_with("Date: "),
		"stamper prepends Date (no Message-ID because the header had one): {text}"
	);
	let first_message_id_line = text
		.lines()
		.find(|line| line.to_ascii_lowercase().starts_with("message-id:"))
		.expect("client Message-ID");
	assert_eq!(
		first_message_id_line, "message-id: <client@example.org>",
		"the only Message-ID before the blank line is the client's: {text}"
	);
	// The body's "Message-ID: not a header" line is preserved unchanged.
	assert!(text.contains("Message-ID: not a header in the body"));
}

/// A folded `Date:` header (the field value continues on the next line,
/// which starts with WSP) is still recognised as present. Pinning the
/// RFC 5322 fold rule so a wrapped Date does not trigger a duplicate
/// stamp.
#[test]
fn a_folded_date_header_is_recognised() {
	let data = b"Date: Mon, 01 Jan\r\n 2024\r\n\
Message-ID: <client@example.org>\r\nSubject: hi\r\n\r\nbody\r\n";
	let stamped = ensure_submission_headers(data, "example.org", at(1_780_662_896));
	// Date and Message-ID are both already there (Date is folded), so the
	// output equals the input byte-for-byte.
	assert_eq!(stamped, data);
}

/// A minimal RFC 5322 date-time parser: the verifier only needs to know
/// that the stamper's `Date:` value is well-formed. `chrono` is not in
/// the dependency tree; the parser only checks the shape.
fn chrono_parse(value: &str) -> bool {
	let Some((weekday, rest)) = value.split_once(", ") else {
		return false;
	};
	if !matches!(
		weekday,
		"Mon" | "Tue" | "Wed" | "Thu" | "Fri" | "Sat" | "Sun"
	) {
		return false;
	}
	// `rest` is `DD Mon YYYY HH:MM:SS ±ZZZZ`. Find the year (the fourth
	// whitespace-separated token) and then the time+zone pair.
	let tokens: Vec<&str> = rest.split_whitespace().collect();
	if tokens.len() != 5 {
		return false;
	}
	let time = tokens[3];
	let zone = tokens[4];
	if time.len() != 8
		|| time.as_bytes().get(2) != Some(&b':')
		|| time.as_bytes().get(5) != Some(&b':')
		|| !time.as_bytes()[..2].iter().all(u8::is_ascii_digit)
		|| !time.as_bytes()[3..5].iter().all(u8::is_ascii_digit)
		|| !time.as_bytes()[6..8].iter().all(u8::is_ascii_digit)
	{
		return false;
	}
	if !(zone.starts_with('+') || zone.starts_with('-')) {
		return false;
	}
	if !tokens[0].chars().all(|c| c.is_ascii_digit()) {
		return false;
	}
	if !tokens[2].chars().all(|c| c.is_ascii_digit()) {
		return false;
	}
	true
}

/// An LF-only message (no CR) is still split correctly: the blank-line
/// separator is `\n\n`, the header block ends at the first one and the
/// stamper does not split a body line in two. Pinning the "CRLF
/// or LF" requirement.
#[test]
fn lf_only_messages_are_split_correctly() {
	let data = b"From: alice@example.org\nSubject: hi\n\nbody\n";
	let stamped = ensure_submission_headers(data, "example.org", at(1_780_662_896));
	let text = std::str::from_utf8(&stamped).expect("ascii");
	let message_id_count = text
		.lines()
		.filter(|line| line.starts_with("Message-ID:"))
		.count();
	assert_eq!(message_id_count, 1, "exactly one Message-ID line: {text}");
	assert!(text.contains("body\n"));
}
