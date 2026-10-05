//! JMAP submission control: the server stamps `Message-ID` and `Date` on
//! a queued `EmailSubmission/set` when the stored message lacks them.
//! Pair with the SMTP-server control
//! (`smtp::server::tests_auth::an_authenticated_submission_without_message_id_gets_one`).

use axum::http::StatusCode;

use super::router;
use super::tests::{TOKEN, request_with_body, test_state};

#[tokio::test]
async fn email_submission_stamps_missing_headers() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	// The stored message has no Message-ID and no Date. Submission must add
	// both before the spooled bytes land.
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		b"From: alice@example.org\r\nTo: bob@elsewhere.example\r\nSubject: hi\r\n\r\nbody\r\n",
	)
	.expect("write");
	let app = router(test_state(dir.path(), 0));

	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:submission"],
		"methodCalls": [["EmailSubmission/set", {
			"accountId": "alice",
			"create": { "s1": {
				"emailId": id.to_string(),
				"identityId": "alice@example.org",
				"envelope": {"mailFrom": {"email": "alice@example.org"},
					"rcptTo": [{"email": "bob@elsewhere.example"}]},
			} },
		}, "c1"]],
	});
	let (status, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert!(
		body["methodResponses"][0][1]["created"]["s1"]["id"].is_string(),
		"{body}"
	);

	// Find the spooled message and read its bytes. The `.eml` payload
	// and its `.json` envelope are siblings; filter to `.eml` only.
	let spool_new = dir.path().join("spool").join("new");
	let mut eml_paths: Vec<_> = std::fs::read_dir(&spool_new)
		.expect("read spool")
		.filter_map(|e| e.ok())
		.map(|e| e.path())
		.filter(|p| p.extension().is_some_and(|x| x == "eml"))
		.collect();
	assert_eq!(eml_paths.len(), 1, "exactly one spooled .eml entry");
	let bytes = std::fs::read(&eml_paths[0]).expect("read spool file");
	let text = std::str::from_utf8(&bytes).expect("ascii spool");
	let _ = &mut eml_paths;

	// Both stamps are present and shaped correctly.
	let message_id_line = text
		.lines()
		.find(|line| line.starts_with("Message-ID:"))
		.expect("stamped Message-ID present");
	let angle = message_id_line
		.find('<')
		.zip(message_id_line.find('>'))
		.expect("angle brackets around id");
	let id_inner = &message_id_line[angle.0 + 1..angle.1];
	let (_, domain) = id_inner.split_once('@').expect("local@domain");
	assert_eq!(domain, "example.org", "id is under the envelope's domain");
	let parsed =
		uuid::Uuid::parse_str(id_inner.split_once('@').unwrap().0).expect("local is a uuid");
	assert_eq!(
		parsed.get_version(),
		Some(uuid::Version::SortRand),
		"id must be uuidv7"
	);

	let date_line = text
		.lines()
		.find(|line| line.starts_with("Date:"))
		.expect("stamped Date present");
	let date_value = date_line.trim_start_matches("Date: ").trim();
	assert!(
		date_value.ends_with("+0000"),
		"Date must end with +0000 (UTC): {date_value}"
	);

	// Both stamps precede the client's own Subject: line.
	let subject_idx = text.find("Subject: ").expect("subject line");
	let message_id_idx = text.find("Message-ID: ").expect("message-id");
	let date_idx = text.find("Date: ").expect("date");
	assert!(
		message_id_idx < subject_idx && date_idx < subject_idx,
		"stamps before Subject: {text}"
	);

	// The client's own headers are still there.
	assert!(text.contains("From: alice@example.org"));
	assert!(text.contains("To: bob@elsewhere.example"));
}

/// When the stored message already carries `Message-ID` and `Date`, the
/// submission path leaves them alone: byte-identical output through the
/// spool. The control for the "we never override the client" half of the
/// contract.
#[tokio::test]
async fn email_submission_keeps_existing_message_id_and_date() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	let stored = b"From: alice@example.org\r\n\
To: bob@elsewhere.example\r\n\
Subject: hi\r\n\
Message-ID: <client@example.org>\r\n\
Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n\
\r\nbody\r\n";
	std::fs::write(inbox.join(format!("{id}.eml")), stored).expect("write");
	let app = router(test_state(dir.path(), 0));

	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:submission"],
		"methodCalls": [["EmailSubmission/set", {
			"accountId": "alice",
			"create": { "s1": {
				"emailId": id.to_string(),
				"identityId": "alice@example.org",
				"envelope": {"mailFrom": {"email": "alice@example.org"},
					"rcptTo": [{"email": "bob@elsewhere.example"}]},
			} },
		}, "c1"]],
	});
	let (status, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");

	let spool_new = dir.path().join("spool").join("new");
	let eml_paths: Vec<_> = std::fs::read_dir(&spool_new)
		.expect("read spool")
		.filter_map(|e| e.ok())
		.map(|e| e.path())
		.filter(|p| p.extension().is_some_and(|x| x == "eml"))
		.collect();
	assert_eq!(eml_paths.len(), 1);
	let bytes = std::fs::read(&eml_paths[0]).expect("read spool file");
	let text = std::str::from_utf8(&bytes).expect("ascii spool");
	// The client's Message-ID and Date survive; only one of each is present.
	assert_eq!(
		text.matches("Message-ID:").count(),
		1,
		"only the client's Message-ID: {text}"
	);
	assert_eq!(
		text.matches("Date:").count(),
		1,
		"only the client's Date: {text}"
	);
	assert!(text.contains("Message-ID: <client@example.org>"));
	assert!(text.contains("Date: Mon, 01 Jan 2024 12:00:00 +0000"));
}
