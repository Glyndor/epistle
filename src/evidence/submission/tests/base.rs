use super::*;

fn message(headers: &str, recipients: &[&str]) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "news@example.org".into(),
		recipients: recipients.iter().map(|r| r.to_string()).collect(),
		data: format!("From: news@example.org\r\n{headers}Subject: s\r\n\r\nbody\r\n").into_bytes(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: Vec::new(),
	}
}

const ONE_CLICK: &str = "List-Unsubscribe: <https://example.org/u>\r\n\
	List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n";

fn marketing() -> ClassSources {
	ClassSources {
		explicit: Some(MailClass::Marketing),
		..ClassSources::default()
	}
}

#[test]
fn the_class_comes_from_the_server_and_the_header_is_removed() {
	let mut submitted = message("Epistle-Class: transactional\r\n", &["a@example.net"]);
	let prepared = prepare(
		&mut submitted,
		ClassSources::default(),
		None,
		&Policy::default(),
		None,
	)
	.expect("prepared");
	assert_eq!(prepared.class, MailClass::Personal);
	let text = String::from_utf8(submitted.data).expect("utf8");
	assert!(
		!text.contains("Epistle-Class"),
		"the class header reached the queue"
	);
}

#[test]
fn marketing_without_one_click_is_refused() {
	let mut submitted = message("", &["a@example.net"]);
	assert_eq!(
		prepare(&mut submitted, marketing(), None, &Policy::default(), None),
		Err(MarketingRefusal::NoUnsubscribeUri)
	);
}

/// A list address sending marketing mail it already published a one-click
/// unsubscribe for: the list block must not replace that URL with a mailto
/// and refuse the message over it.
#[test]
fn marketing_from_a_list_keeps_the_one_click_the_client_chose() {
	let directory = crate::smtp::directory::Directory::default().with_aliases([(
		"news@example.org".to_string(),
		crate::smtp::directory::AliasSpec {
			members: vec!["alice@example.org".to_string()],
			senders: Vec::new(),
			hidden: false,
			list_id: Some("news.example.org".to_string()),
		},
	)]);
	let mut submitted = message(ONE_CLICK, &["a@example.net"]);
	prepare(
		&mut submitted,
		marketing(),
		None,
		&Policy::default(),
		Some(&directory),
	)
	.expect("a list that honours one-click is not refused");
	assert_eq!(
		crate::smtp::trace::header_values(&submitted.data, "list-unsubscribe"),
		vec!["<https://example.org/u>".to_string()]
	);
	assert_eq!(
		crate::smtp::trace::header_values(&submitted.data, "list-post"),
		vec!["<mailto:news@example.org>".to_string()],
		"the list block still says what the list is"
	);
}

#[test]
fn marketing_is_marked_bulk_and_suppressed_recipients_are_dropped() {
	let dir = tempfile::tempdir().expect("tempdir");
	let list = crate::queue::SuppressionList::open(dir.path()).expect("list");
	list.suppress("gone@example.net");
	list.suppress_for_because(
		"news@example.org",
		"unsubscribed@example.net",
		"550 5.1.1",
		1,
	);
	let mut submitted = message(
		ONE_CLICK,
		&[
			"kept@example.net",
			"gone@example.net",
			"unsubscribed@example.net",
		],
	);
	let prepared = prepare(
		&mut submitted,
		marketing(),
		Some(dir.path()),
		&Policy::default(),
		None,
	)
	.expect("prepared");
	assert_eq!(prepared.class, MailClass::Marketing);
	assert_eq!(
		prepared.suppressed,
		vec!["gone@example.net", "unsubscribed@example.net"]
	);
	assert_eq!(submitted.recipients, vec!["kept@example.net"]);
	assert!(
		submitted.data.starts_with(b"Precedence: bulk\r\n"),
		"bulk was not marked"
	);
}

#[test]
fn other_classes_keep_suppressed_recipients_for_the_worker() {
	let dir = tempfile::tempdir().expect("tempdir");
	crate::queue::SuppressionList::open(dir.path())
		.expect("list")
		.suppress("gone@example.net");
	let mut submitted = message("", &["gone@example.net"]);
	let sources = ClassSources {
		explicit: Some(MailClass::Transactional),
		..ClassSources::default()
	};
	let prepared = prepare(
		&mut submitted,
		sources,
		Some(dir.path()),
		&Policy::default(),
		None,
	)
	.expect("prepared");
	assert!(prepared.suppressed.is_empty());
	assert_eq!(submitted.recipients, vec!["gone@example.net"]);
}

fn raw_message(data: &[u8]) -> AcceptedMessage {
	AcceptedMessage {
		reverse_path: "news@example.org".into(),
		recipients: vec!["a@example.net".into()],
		data: data.to_vec(),
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		sender_verified: true,
		no_dsn: Vec::new(),
	}
}

#[test]
fn the_rest_submission_refuses_malformed_header_lines() {
	for raw in [
		b" From: victim@example.org\r\nFrom: news@example.org\r\n\r\nbody\r\n".as_slice(),
		b"From: news@example.org\r\n:From: victim@example.org\r\n\r\nbody\r\n".as_slice(),
		b"From: news@example.org\r\nGarbage\r\n Fr om: victim@example.org\r\n\r\nbody\r\n"
			.as_slice(),
	] {
		let mut submitted = raw_message(raw);
		let before = submitted.data.clone();
		let refusal = prepare(
			&mut submitted,
			ClassSources::default(),
			None,
			&Policy::default(),
			None,
		)
		.expect_err("malformed header lines");
		assert_eq!(
			refusal.message(),
			"submission header lines must follow RFC 5322 field and folding syntax"
		);
		assert_eq!(
			submitted.data, before,
			"the message changed before the refusal"
		);
	}
}

#[test]
fn the_rest_submission_keeps_a_body_after_a_leading_blank_line() {
	let mut submitted = raw_message(b"\r\nX-Epistle: forged\r\nbody\r\n");
	prepare(
		&mut submitted,
		ClassSources::default(),
		None,
		&Policy::default(),
		None,
	)
	.expect("body-only message");
	let boundary = submitted
		.data
		.windows(4)
		.position(|w| w == b"\r\n\r\n")
		.expect("header boundary");
	assert_eq!(
		&submitted.data[boundary + 4..],
		b"X-Epistle: forged\r\nbody\r\n"
	);
}

#[test]
fn the_rest_submission_does_not_read_a_body_after_a_leading_blank_line_as_headers() {
	for raw in [
		b"\r\nHello world: x\r\n".as_slice(),
		b"\nHello world: x\n".as_slice(),
	] {
		let mut submitted = raw_message(raw);
		prepare(
			&mut submitted,
			ClassSources::default(),
			None,
			&Policy::default(),
			None,
		)
		.expect("body-only message");
	}
}

#[test]
fn the_rest_submission_reports_ambiguous_identity_names_and_invalid_encoding() {
	// The old date vector is safe in 1.0; malformed identity names still
	// have to be refused, with the original bytes left intact.
	for (raw, expected) in [
		(
			b"From: news@example.org\r\nFr om: victim@example.net\r\n\r\nbody\r\n".as_slice(),
			"submission header field names must use printable ASCII without embedded whitespace",
		),
		(
			b"From: news@example.org\r\nSen der: victim@example.net\r\n\r\nbody\r\n".as_slice(),
			"submission header field names must use printable ASCII without embedded whitespace",
		),
		(
			b"From: news@example.org\r\nSubject: caf\xe9\r\n\r\nx".as_slice(),
			"I cannot accept submission headers that are not UTF-8",
		),
	] {
		let mut submitted = raw_message(raw);
		let refusal = prepare(
			&mut submitted,
			ClassSources::default(),
			None,
			&Policy::default(),
			None,
		)
		.expect_err("invalid headers");
		assert_eq!(refusal.message(), expected);
		assert_eq!(submitted.data, raw);
	}
}

#[test]
fn the_rest_submission_refuses_ambiguous_identity_names_across_crlf_normalization() {
	let raw = b"From: news@example.org\nFr om: victim@example.net\n\nbody\n";
	assert_eq!(
		crate::smtp::identification::reject_ambiguous_headers(raw),
		Err(MarketingRefusal::AmbiguousHeaderName)
	);
	let normalized = crate::util::header_block::outbound_crlf(raw);
	assert_eq!(
		crate::smtp::identification::reject_ambiguous_headers(&normalized),
		Err(MarketingRefusal::AmbiguousHeaderName)
	);
	let mut submitted = raw_message(raw);
	let refusal = prepare(
		&mut submitted,
		ClassSources::default(),
		None,
		&Policy::default(),
		None,
	)
	.expect_err("I expect the ambiguous identity to be refused before changing the message");
	assert_eq!(
		refusal.message(),
		"submission header field names must use printable ASCII without embedded whitespace"
	);
	assert_eq!(submitted.data, raw);
}

#[test]
fn the_rest_submission_keeps_date_following_body_identities_out_after_normalization() {
	for ending in ["\n", "\r\n"] {
		let raw = format!(
			"From: news@example.org{ending}Date: Mon, 1 Jan 2020 00:00:00 -0500x{ending}{ending}From: victim@example.net{ending}Sender: victim@example.net{ending}"
		);
		let mut submitted = raw_message(raw.as_bytes());
		prepare(
			&mut submitted,
			ClassSources::default(),
			None,
			&Policy::default(),
			None,
		)
		.expect("1.0 keeps both body identities outside the header block");
		assert_eq!(
			crate::dmarc::author::author(&submitted.data),
			crate::dmarc::author::Author::Addresses(vec!["news@example.org".to_string()])
		);
		let parsed = mail_parser::MessageParser::default()
			.parse_headers(&submitted.data)
			.expect("headers");
		assert_eq!(parsed.headers().all("From").count(), 1);
		assert!(!parsed.headers().contains("Sender"));
		assert!(
			submitted
				.data
				.ends_with(b"\r\n\r\nFrom: victim@example.net\r\nSender: victim@example.net\r\n")
		);
	}
}

#[test]
fn the_rest_submission_refuses_a_body_with_a_loose_cr_or_a_nul() {
	for raw in [
		b"From: news@example.org\r\n\r\nhello\r.\r\nbody\r\n".as_slice(),
		b"From: news@example.org\r\n\r\nbody\r".as_slice(),
		b"From: news@example.org\r\n\r\nbo\0dy\r\n".as_slice(),
	] {
		let mut submitted = raw_message(raw);
		let before = submitted.data.clone();
		let refusal = prepare(
			&mut submitted,
			ClassSources::default(),
			None,
			&Policy::default(),
			None,
		)
		.expect_err("loose body framing");
		assert_eq!(refusal, MarketingRefusal::AmbiguousLineFraming);
		assert_eq!(submitted.data, before);
	}
}
