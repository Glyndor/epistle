use super::*;

fn counted_messages(dir: &Path, count: usize) {
	let inbox = dir.join("accounts/alice/new");
	std::fs::create_dir_all(&inbox).expect("inbox");
	// Preflight counts .eml files before opening snapshots; no bodies or journals are needed.
	for index in 0..count {
		let id = uuid::Uuid::from_u128(index as u128 + 1);
		std::fs::File::create(inbox.join(format!("{id}.eml"))).expect("counted message");
	}
}

fn limit(response: &Value, name: &str) {
	error(response, "requestTooLarge");
	assert_eq!(response[1]["limit"], name, "{response}");
	assert!(response[1]["description"].is_string(), "{response}");
}

#[tokio::test]
async fn q45_message_budget_is_a_method_error_and_q53_replay_is_bounded() {
	let dir = tempfile::tempdir().expect("tempdir");
	// An account gets a change journal with its first message, and only then
	// does its query state become a cursor queryChanges can replay.
	append(
		dir.path(),
		"INBOX",
		EPOCH,
		&[],
		b"Subject: first\r\n\r\nbody\r\n",
	);
	let app = router(test_state(dir.path(), 0));
	let since = query(&app, json!({})).await["queryState"].clone();
	let unchanged = call(
		&app,
		"Email/queryChanges",
		json!({"sinceQueryState": since}),
	)
	.await;
	assert_eq!(
		unchanged[0], "Email/queryChanges",
		"cursor must be replayable: {unchanged}"
	);
	assert_eq!(unchanged[1]["added"], json!([]));
	counted_messages(dir.path(), 99_999);
	// Exactly 100,000 passes the general count guard and reaches the smaller text budget.
	let response = call(&app, "Email/query", json!({"filter": {"text": "needle"}})).await;
	limit(&response, "maxEmailQuerySearchMessages");
	let extra = dir
		.path()
		.join("accounts/alice/new")
		.join(format!("{}.eml", uuid::Uuid::from_u128(100_001)));
	std::fs::File::create(extra).expect("one over the count limit");
	let responses = envelope(
		&app,
		json!([
			["Email/query", {"accountId": "alice", "limit": 1}, "c1"],
			["Core/echo", {"survived": true}, "echo"]
		]),
	)
	.await;
	assert_eq!(responses.as_array().expect("responses").len(), 2);
	limit(&responses[0], "maxEmailQueryResults");
	assert_eq!(responses[0][2], "c1");
	assert_eq!(
		responses[1],
		json!(["Core/echo", {"survived": true}, "echo"])
	);
	// A valid since state ensures rejection is due to bounded replay, not an invalid cursor.
	let response = call(
		&app,
		"Email/queryChanges",
		json!({"sinceQueryState": since}),
	)
	.await;
	error(&response, "cannotCalculateChanges");
}

#[tokio::test]
async fn q46_mailbox_budget_counts_inbox_and_all_folders() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let folders = dir.path().join("accounts/alice/folders");
	for index in 0..999 {
		std::fs::create_dir_all(folders.join(format!("box-{index}")).join("new")).expect("folder");
	}
	assert_eq!(mailbox::list(dir.path(), "alice").len(), 1000);
	let at_limit = query(&app, json!({})).await;
	assert_eq!(at_limit["ids"], json!([]));
	std::fs::create_dir_all(folders.join("one-over/new")).expect("extra mailbox");
	let response = call(&app, "Email/query", json!({})).await;
	limit(&response, "maxEmailQueryMailboxes");
	// A scoped query examines only its mailbox, not every folder in the account.
	let scoped = query(&app, json!({"filter": {"inMailbox": "INBOX"}})).await;
	assert_eq!(scoped["ids"], json!([]));
}

#[tokio::test]
async fn q47_text_search_message_budget_applies_before_filtering_or_paging() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	counted_messages(dir.path(), 10_001);
	let response = call(
		&app,
		"Email/query",
		json!({
			"filter": {"text": "absent"}, "limit": 0, "calculateTotal": false
		}),
	)
	.await;
	limit(&response, "maxEmailQuerySearchMessages");
}

#[tokio::test]
async fn q48_text_search_byte_budget_accepts_boundary_and_rejects_one_over() {
	for bytes in [16 * 1024 * 1024u64, 16 * 1024 * 1024 + 1] {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = router(test_state(dir.path(), 0));
		let mut ids = Vec::new();
		// Two individually small messages prove that bytes accumulate across the query.
		for index in 0..2 {
			let seconds = EPOCH + index;
			let id = append(
				dir.path(),
				"INBOX",
				seconds,
				&[],
				b"Subject: needle\r\n\r\nbody",
			);
			let path = mailbox::mailbox_dir(dir.path(), "alice", "INBOX")
				.expect("inbox")
				.join(format!("{id}.eml"));
			let file = std::fs::OpenOptions::new()
				.write(true)
				.open(path)
				.expect("message");
			// Sparse bodies provide logical sizes without large fixtures in the repository.
			let size = if index == 0 {
				8 * 1024 * 1024
			} else {
				bytes - 8 * 1024 * 1024
			};
			file.set_len(size).expect("sparse length");
			file.set_modified(UNIX_EPOCH + Duration::from_secs(seconds))
				.expect("fixed date");
			ids.push(id);
		}
		ids.reverse();
		let response = call(
			&app,
			"Email/query",
			json!({"filter": {"subject": "needle"}}),
		)
		.await;
		if bytes == 16 * 1024 * 1024 {
			assert_eq!(response[0], "Email/query", "{response}");
			assert_eq!(response[1]["ids"], json!(ids));
		} else {
			limit(&response, "maxEmailQuerySearchBytes");
			// Size alone does not prevent a metadata-only query.
			assert_eq!(query(&app, json!({})).await["ids"], json!(ids));
		}
	}
}

#[tokio::test]
async fn q49_header_budget_accepts_boundary_and_rejects_one_over() {
	for bytes in [256 * 1024, 256 * 1024 + 1] {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = router(test_state(dir.path(), 0));
		let mut raw = b"Subject: needle\r\nX-Padding: ".to_vec();
		// split_at_blank_line includes the last header's CRLF, but not the blank CRLF.
		raw.resize(bytes - 2, b'x');
		raw.extend_from_slice(b"\r\n\r\nbody");
		let (header, _) = crate::util::header_block::split_at_blank_line(&raw);
		assert_eq!(
			header.len(),
			bytes,
			"fixture must straddle the exact header limit"
		);
		let id = append(dir.path(), "INBOX", EPOCH, &[], &raw);
		let response = call(
			&app,
			"Email/query",
			json!({"filter": {"subject": "needle"}}),
		)
		.await;
		if bytes == 256 * 1024 {
			assert_eq!(response[0], "Email/query", "{response}");
			assert_eq!(response[1]["ids"], json!([id]));
		} else {
			limit(&response, "maxEmailQuerySearchHeaderBytes");
		}
	}
}

#[tokio::test]
async fn q50_cost_error_preserves_results_before_and_after_it_in_the_envelope() {
	let f = Fixture::new();
	let raw = format!("Subject: {}\r\n\r\nbody", "x".repeat(256 * 1024));
	append(f.dir.path(), "Huge", EPOCH, &[], raw.as_bytes());
	let responses = envelope(
		&f.app,
		json!([
			["Email/query", {"accountId": "alice", "filter": {"inMailbox": "Archive"}}, "before"],
			["Email/query", {"accountId": "alice", "filter": {"inMailbox": "Huge", "text": "x"}}, "over"],
			["Email/query", {"accountId": "alice", "filter": {"inMailbox": "INBOX"}, "limit": 1}, "after"],
			["Core/echo", {"ok": 42}, "echo"]
		]),
	)
	.await;
	assert_eq!(responses.as_array().expect("responses").len(), 4);
	assert_eq!(responses[0][0], "Email/query", "{responses}");
	assert_eq!(responses[0][1]["ids"], json!([f.new]));
	assert_eq!(responses[0][2], "before");
	limit(&responses[1], "maxEmailQuerySearchHeaderBytes");
	assert_eq!(responses[1][2], "over");
	assert_eq!(responses[2][0], "Email/query");
	assert_eq!(responses[2][1]["ids"], json!([f.middle]));
	assert_eq!(responses[2][2], "after");
	assert_eq!(responses[3], json!(["Core/echo", {"ok": 42}, "echo"]));
}

#[tokio::test]
async fn q55_decryption_failure_never_returns_a_silent_partial_result() {
	let f = Fixture::new();
	let foreign_crypto = MessageCrypto::for_test(&[17; 32]);
	let id = mailbox::append(
		f.dir.path(),
		"alice",
		"Broken",
		&[],
		b"Subject: needle\r\n\r\nneedle",
		&foreign_crypto,
	)
	.expect("encrypted message");
	// The API has no key for this envelope. Other matching mail remains readable.
	let response = call(
		&f.app,
		"Email/query",
		json!({"filter": {"text": "SubjectNeedle"}}),
	)
	.await;
	error(&response, "serverFail");
	assert_eq!(
		query(
			&f.app,
			json!({"filter": {"inMailbox": "INBOX", "text": "SubjectNeedle"}})
		)
		.await["ids"],
		json!([f.middle, f.old])
	);
	assert_eq!(
		query(&f.app, json!({"filter": {"inMailbox": "Broken"}})).await["ids"],
		json!([id.to_string()])
	);
}
