//! The From field of what the API queues is the one the account was
//! checked against: `EmailSubmission/set` refuses a stored email whose
//! From the account does not own, and `/api/v1/send` writes the single
//! From itself.

use super::router;
use super::tests::{TOKEN, request_with_body, test_state};
use crate::dmarc::author::{Author, author};
use crate::storage::FsSpool;
use axum::http::StatusCode;

/// Store an email with `headers` for alice and submit it from her own
/// envelope address; return the method response.
async fn submit(headers: &str) -> (serde_json::Value, tempfile::TempDir) {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		format!("{headers}To: carol@elsewhere.example\r\nSubject: hi\r\n\r\nbody\r\n"),
	)
	.expect("write");
	let app = router(test_state(dir.path(), 0));
	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:submission"],
		"methodCalls": [["EmailSubmission/set", {
			"accountId": "alice",
			"create": { "s1": {
				"emailId": id.to_string(),
				"envelope": {"mailFrom": {"email": "alice@example.org"},
					"rcptTo": [{"email": "carol@elsewhere.example"}]},
			} },
		}, "c1"]],
	});
	let (status, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	(body["methodResponses"][0][1].clone(), dir)
}

/// The authors of everything in the spool under `dir`.
fn spooled_authors(dir: &std::path::Path) -> Vec<Author> {
	let spool = FsSpool::open(dir).expect("spool");
	let ids = spool.list().expect("list");
	ids.into_iter()
		.map(|id| author(&spool.load(id).expect("load").data))
		.collect()
}

#[tokio::test]
async fn submission_of_an_email_from_the_account_is_queued() {
	let (response, dir) = submit("From: Alice <alice@example.org>\r\n").await;
	assert!(response["created"]["s1"]["id"].is_string(), "{response}");
	assert_eq!(
		spooled_authors(dir.path()),
		[Author::Addresses(vec!["alice@example.org".to_string()])]
	);
}

#[tokio::test]
async fn submission_of_an_email_from_someone_else_is_forbidden() {
	for headers in [
		"From: bob@elsewhere.example\r\n",
		"From: alice@example.org\r\nFrom : bob@elsewhere.example\r\n",
		"From: alice@example.org, bob@elsewhere.example\r\n",
		"",
	] {
		let (response, dir) = submit(headers).await;
		assert_eq!(
			response["notCreated"]["s1"]["type"], "forbiddenFrom",
			"{headers:?}: {response}"
		);
		assert!(spooled_authors(dir.path()).is_empty(), "{headers:?}");
	}
}

#[tokio::test]
async fn api_send_queues_exactly_the_checked_from() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let injected = serde_json::json!({
		"from": "alice@example.org", "to": ["b@x.example"],
		"subject": "x\r\nFrom: ceo@example.org", "text": "hi",
	});
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(injected),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	assert!(spooled_authors(dir.path()).is_empty());

	let plain = serde_json::json!({
		"from": "alice@example.org", "to": ["b@x.example"],
		"subject": "hello", "text": "hi",
	});
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(plain),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(
		spooled_authors(dir.path()),
		[Author::Addresses(vec!["alice@example.org".to_string()])]
	);
}
