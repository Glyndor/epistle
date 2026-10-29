	use super::*;
	use std::time::UNIX_EPOCH;

	fn vacation() -> Vacation<'static> {
		Vacation {
			reason: "I am away until Monday.",
			subject: None,
			from: None,
			user_address: "alice@example.org",
			html_body: None,
		}
	}

	#[test]
	fn builds_auto_reply_with_null_sender() {
		let reply = build_response(
			&vacation(),
			"bob@example.net",
			&Original {
				subject: Some("Lunch?"),
				message_id: Some("<abc@example.net>"),
				references: None,
			},
			UNIX_EPOCH,
		)
		.expect("reply");
		assert_eq!(reply.reverse_path, "");
		assert_eq!(reply.recipients, vec!["bob@example.net".to_string()]);
		let body = String::from_utf8(reply.data).expect("ascii");
		assert!(body.contains("From: <alice@example.org>"), "{body}");
		assert!(body.contains("To: <bob@example.net>"), "{body}");
		assert!(body.contains("Subject: Auto: Lunch?"), "{body}");
		assert!(
			body.contains("Auto-Submitted: auto-replied (vacation)"),
			"{body}"
		);
		assert!(body.contains("In-Reply-To: <abc@example.net>"), "{body}");
		assert!(body.contains("I am away until Monday."), "{body}");
	}

	#[test]
	fn explicit_subject_and_from_override() {
		let vacation = Vacation {
			reason: "Away.",
			subject: Some("Out of office"),
			from: Some("assistant@example.org"),
			user_address: "alice@example.org",
			html_body: None,
		};
		let reply = build_response(
			&vacation,
			"bob@example.net",
			&Original {
				subject: Some("Hi"),
				message_id: None,
				references: None,
			},
			UNIX_EPOCH,
		)
		.expect("reply");
		let body = String::from_utf8(reply.data).expect("ascii");
		assert!(body.contains("Subject: Out of office"), "{body}");
		assert!(body.contains("From: <assistant@example.org>"), "{body}");
		// No Message-ID on the original → no In-Reply-To.
		assert!(!body.contains("In-Reply-To:"), "{body}");
	}

	#[test]
	fn default_subject_without_original() {
		let reply = build_response(
			&vacation(),
			"bob@example.net",
			&Original {
				subject: None,
				message_id: None,
				references: None,
			},
			UNIX_EPOCH,
		)
		.expect("reply");
		let body = String::from_utf8(reply.data).expect("ascii");
		assert!(body.contains("Subject: Auto: Re: your message"), "{body}");
	}

	#[test]
	fn html_body_produces_multipart_alternative() {
		let vacation = Vacation {
			reason: "Away.",
			subject: None,
			from: None,
			user_address: "alice@example.org",
			html_body: Some("<p>Away.</p>"),
		};
		let reply = build_response(
			&vacation,
			"bob@example.net",
			&Original {
				subject: None,
				message_id: None,
				references: None,
			},
			UNIX_EPOCH,
		)
		.expect("reply");
		let body = String::from_utf8(reply.data).expect("ascii");
		assert!(body.contains("multipart/alternative"), "{body}");
		assert!(body.contains("text/plain"), "{body}");
		assert!(body.contains("<p>Away.</p>"), "{body}");
	}

	#[test]
	fn subject_with_crlf_does_not_inject_headers() {
		// The original message's Subject carries CRLF and a forged Bcc. The
		// built reply must not contain a header that starts a line.
		let reply = build_response(
			&vacation(),
			"bob@example.net",
			&Original {
				subject: Some("foo\r\nBcc: attacker@evil.example"),
				message_id: Some("<abc@example.net>"),
				references: None,
			},
			UNIX_EPOCH,
		)
		.expect("reply");
		let body = String::from_utf8(reply.data).expect("ascii");
		// No injected header at the start of any line.
		assert!(!body.contains("\r\nBcc: attacker@evil.example"), "{body}");
		assert!(!body.contains("\r\nX-Injected:"), "{body}");
		// The Subject line itself must not contain raw CR or LF: the injected
		// CRLF was flattened to spaces, so the value sits on one line.
		let subject_line = body
			.lines()
			.find(|line| line.starts_with("Subject:"))
			.expect("Subject line present");
		assert!(!subject_line.contains('\r'), "{subject_line}");
		assert!(!subject_line.contains('\n'), "{subject_line}");
		assert!(
			subject_line.contains("Bcc: attacker@evil.example"),
			"{subject_line}"
		);
	}

	#[test]
	fn message_id_with_crlf_does_not_inject_headers() {
		// The original message's Message-ID carries CRLF and a forged Bcc.
		let reply = build_response(
			&vacation(),
			"bob@example.net",
			&Original {
				subject: Some("Lunch?"),
				message_id: Some("<abc@example.net>\r\nBcc: attacker@evil.example"),
				references: None,
			},
			UNIX_EPOCH,
		)
		.expect("reply");
		let body = String::from_utf8(reply.data).expect("ascii");
		assert!(!body.contains("\r\nBcc: attacker@evil.example"), "{body}");
		let in_reply_to_line = body
			.lines()
			.find(|line| line.starts_with("In-Reply-To:"))
			.expect("In-Reply-To line present");
		assert!(!in_reply_to_line.contains('\r'), "{in_reply_to_line}");
		assert!(!in_reply_to_line.contains('\n'), "{in_reply_to_line}");
	}

	#[test]
	fn explicit_subject_with_crlf_is_flattened() {
		// A Sieve script's `:subject` parameter is also user-influenced: the
		// same flattening must apply regardless of where the value comes from.
		let vacation = Vacation {
			reason: "Away.",
			subject: Some("Out of office\r\nBcc: attacker@evil.example"),
			from: None,
			user_address: "alice@example.org",
			html_body: None,
		};
		let reply = build_response(
			&vacation,
			"bob@example.net",
			&Original {
				subject: None,
				message_id: None,
				references: None,
			},
			UNIX_EPOCH,
		)
		.expect("reply");
		let body = String::from_utf8(reply.data).expect("ascii");
		assert!(!body.contains("\r\nBcc: attacker@evil.example"), "{body}");
		let subject_line = body
			.lines()
			.find(|line| line.starts_with("Subject:"))
			.expect("Subject line present");
		assert!(!subject_line.contains('\r'), "{subject_line}");
		assert!(!subject_line.contains('\n'), "{subject_line}");
	}

	/// A `References` or `Message-ID` of a megabyte of `<` with no `>`: each
	/// opening bracket must not rescan the rest of the header, or one
	/// inbound message costs about 5 * 10^11 byte comparisons.
	#[test]
	fn a_header_full_of_open_brackets_costs_linear_time() {
		let hostile = "<".repeat(1 << 20);
		let (done, finished) = std::sync::mpsc::channel();
		std::thread::spawn(move || {
			let original = Original {
				subject: None,
				message_id: Some(&hostile),
				references: Some(&hostile),
			};
			let reply = build_response(&vacation(), "bob@example.net", &original, UNIX_EPOCH);
			let _ = done.send(reply.is_some());
		});
		let built = finished
			.recv_timeout(std::time::Duration::from_secs(10))
			.expect("the reply is built in linear time");
		assert!(built, "the reply is still sent, without In-Reply-To");
	}

	#[test]
	fn references_keep_the_last_ids_and_drop_junk() {
		let many: String = (0..40)
			.map(|n| format!("<{n}@x> junk < bad id> "))
			.collect();
		let original = Original {
			subject: None,
			message_id: Some("noise <last@x> more"),
			references: Some(&many),
		};
		let reply =
			build_response(&vacation(), "bob@example.net", &original, UNIX_EPOCH).expect("reply");
		let text = String::from_utf8(reply.data).expect("utf-8");
		let unfolded = text.replace("\r\n ", " ");
		let line = unfolded
			.lines()
			.find(|line| line.starts_with("References:"))
			.expect("References line");
		let ids: Vec<&str> = line["References:".len()..].split_whitespace().collect();
		assert_eq!(ids.len(), MAX_REFERENCES + 1, "{line}");
		assert_eq!(ids[0], "<20@x>");
		assert_eq!(ids[MAX_REFERENCES], "<last@x>");
		assert!(text.contains("In-Reply-To: <last@x>\r\n"), "{text}");
	}
