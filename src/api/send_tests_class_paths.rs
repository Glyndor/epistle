//! What each way of submitting does with a class, beyond the happy path:
//! marketing suppression, evidence that cannot be written, a held gate and
//! a class header the client tries to raise.

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::router;
use super::send_tests_class::{send, sent_count, state};
use super::tests::{TOKEN, request_with_body};
use crate::evidence::MailClass;
use crate::storage::FsSpool;

const UNSUBSCRIBE: &str = "List-Unsubscribe: <https://example.org/u?t=1>\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n";

fn marketing_request(to: &[&str]) -> Value {
	json!({
		"class": "marketing",
		"to": to,
		"list_unsubscribe": ["https://example.org/u?t=1"],
		"list_unsubscribe_post": true,
	})
}

/// Stop the evidence log from taking a record today.
fn block_evidence(dir: &std::path::Path) {
	let today = crate::evidence::day::Day::of_epoch(crate::storage::delivery_log::now_epoch());
	std::fs::create_dir_all(
		dir.join("evidence/chain")
			.join(format!("{}.jsonl", today.name())),
	)
	.expect("block the day file");
}

fn queued(dir: &std::path::Path, body: &Value) -> crate::storage::SpoolEntry {
	let id = uuid::Uuid::parse_str(body["queued"].as_str().expect("id")).expect("uuid");
	FsSpool::open(dir).expect("spool").load(id).expect("queued")
}

#[tokio::test]
async fn marketing_drops_suppressed_recipients_and_says_so() {
	let dir = tempfile::tempdir().expect("tempdir");
	crate::queue::SuppressionList::open(dir.path())
		.expect("list")
		.suppress("gone@elsewhere.example");
	let (state, _) = state(dir.path());
	let app = router(state);
	let (status, body) = send(
		&app,
		marketing_request(&["kept@elsewhere.example", "gone@elsewhere.example"]),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["suppressed"], json!(["gone@elsewhere.example"]));
	assert_eq!(
		queued(dir.path(), &body).envelope.recipients.len(),
		1,
		"the suppressed recipient was queued"
	);
	let (status, body) = send(&app, marketing_request(&["gone@elsewhere.example"])).await;
	assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
	assert_eq!(body["error"]["code"], "marketing_refused");
	let (status, body) = send(
		&app,
		json!({"class": "personal", "to": ["gone@elsewhere.example"]}),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(
		body["suppressed"],
		Value::Null,
		"personal mail is not filtered here"
	);
}

#[tokio::test]
async fn transactional_mail_is_refused_when_its_evidence_cannot_be_written() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts/alice")).expect("mkdir");
	let (state, _) = state(dir.path());
	let app = router(state);
	block_evidence(dir.path());
	let (status, body) = send(&app, json!({"class": "transactional"})).await;
	assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
	assert_eq!(body["error"]["code"], "evidence_unavailable");
	let spool = FsSpool::open(dir.path()).expect("spool");
	assert!(spool.list().expect("list").is_empty(), "queued anyway");
	assert_eq!(
		sent_count(dir.path()),
		0,
		"a Sent copy of a refused message"
	);
	let (status, body) = send(&app, json!({"class": "personal"})).await;
	assert_eq!(
		status,
		StatusCode::OK,
		"personal mail keeps flowing: {body}"
	);
}

#[tokio::test]
async fn a_class_header_in_the_request_cannot_raise_the_class() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (state, _) = state(dir.path());
	let app = router(state);
	let (status, body) = send(&app, json!({"headers": {"Epistle-Class": "transactional"}})).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	let (status, body) = send(
		&app,
		json!({"headers": {"X-Epistle-Class": "transactional"}}),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["class"], "personal");
	assert_eq!(
		queued(dir.path(), &body).envelope.class,
		MailClass::Personal
	);
}

/// Submit a drafted message through JMAP and return the method response.
async fn jmap(
	dir: &std::path::Path,
	app: &axum::Router,
	headers: &str,
	rcpts: &[&str],
	class: &str,
) -> Value {
	let inbox = dir.join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let email = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{email}.eml")),
		format!("From: alice@example.org\r\nTo: bob@elsewhere.example\r\n{headers}Subject: Drafted\r\n\r\nbody\r\n"),
	)
	.expect("write draft");
	let rcpt_to: Vec<Value> = rcpts.iter().map(|r| json!({"email": r})).collect();
	let req = json!({
		"using": ["urn:ietf:params:jmap:submission"],
		"methodCalls": [["EmailSubmission/set", {"accountId": "alice", "create": {"s1": {
			"emailId": email.to_string(),
			"envelope": {"mailFrom": {"email": "alice@example.org"}, "rcptTo": rcpt_to},
			"epistle:class": class,
		}}}, "c1"]],
	});
	let (status, body) =
		request_with_body(app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	body["methodResponses"][0][1].clone()
}

#[tokio::test]
async fn jmap_refuses_marketing_without_one_click_and_drops_the_suppressed() {
	let dir = tempfile::tempdir().expect("tempdir");
	crate::queue::SuppressionList::open(dir.path())
		.expect("list")
		.suppress("gone@elsewhere.example");
	let (state, _) = state(dir.path());
	let app = router(state);
	let refused = jmap(
		dir.path(),
		&app,
		"",
		&["kept@elsewhere.example"],
		"marketing",
	)
	.await;
	assert_eq!(
		refused["notCreated"]["s1"]["type"], "forbiddenToSend",
		"{refused}"
	);
	let accepted = jmap(
		dir.path(),
		&app,
		UNSUBSCRIBE,
		&["kept@elsewhere.example", "gone@elsewhere.example"],
		"marketing",
	)
	.await;
	let id = accepted["created"]["s1"]["id"].as_str().expect("created");
	let entry = FsSpool::open(dir.path())
		.expect("spool")
		.load(uuid::Uuid::parse_str(id).expect("uuid"))
		.expect("queued");
	assert_eq!(
		entry.envelope.recipients.len(),
		1,
		"the suppressed one was queued"
	);
	assert!(String::from_utf8_lossy(&entry.data).starts_with("Precedence: bulk\r\n"));
	let all = jmap(
		dir.path(),
		&app,
		UNSUBSCRIBE,
		&["gone@elsewhere.example"],
		"marketing",
	)
	.await;
	assert_eq!(all["notCreated"]["s1"]["type"], "forbiddenToSend", "{all}");
}

#[tokio::test]
async fn jmap_refuses_transactional_mail_it_cannot_record() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (state, service) = state(dir.path());
	let app = router(state);
	service.set_gate(Some("broken".into()));
	let held = jmap(
		dir.path(),
		&app,
		"",
		&["bob@elsewhere.example"],
		"transactional",
	)
	.await;
	assert_eq!(
		held["notCreated"]["s1"]["type"], "serverUnavailable",
		"{held}"
	);
	service.set_gate(None);
	block_evidence(dir.path());
	let blocked = jmap(
		dir.path(),
		&app,
		"",
		&["bob@elsewhere.example"],
		"transactional",
	)
	.await;
	assert_eq!(
		blocked["notCreated"]["s1"]["type"], "serverUnavailable",
		"{blocked}"
	);
	let spool = FsSpool::open(dir.path()).expect("spool");
	assert!(spool.list().expect("list").is_empty(), "queued anyway");
}

const CLASSES: [MailClass; 3] = [
	MailClass::Personal,
	MailClass::Marketing,
	MailClass::Transactional,
];

fn stricter(a: MailClass, b: MailClass) -> MailClass {
	let rank = |class: MailClass| CLASSES.iter().position(|c| *c == class);
	if rank(a) >= rank(b) { a } else { b }
}

/// A server whose account `alice` is bound to `floor`.
fn bound_state(dir: &std::path::Path, floor: MailClass) -> axum::Router {
	std::fs::create_dir_all(dir.join("accounts/alice")).expect("mkdir");
	crate::evidence::bindings::update(dir, |bindings| {
		bindings.accounts.insert("alice".into(), floor);
	})
	.expect("bind");
	router(state(dir).0)
}

#[tokio::test]
async fn over_rest_the_bound_class_is_a_floor_for_every_requested_class() {
	for floor in CLASSES {
		for asked in CLASSES {
			let dir = tempfile::tempdir().expect("tempdir");
			let app = bound_state(dir.path(), floor);
			let mut request = marketing_request(&["bob@elsewhere.example"]);
			request["class"] = json!(asked.as_str());
			let (status, body) = send(&app, request).await;
			assert_eq!(status, StatusCode::OK, "{floor} / {asked}: {body}");
			assert_eq!(
				body["class"],
				stricter(floor, asked).as_str(),
				"bound to {floor}, the request asks {asked}"
			);
		}
	}
}

#[tokio::test]
async fn over_jmap_the_bound_class_is_a_floor_for_every_requested_class() {
	for floor in CLASSES {
		for asked in CLASSES {
			let dir = tempfile::tempdir().expect("tempdir");
			let app = bound_state(dir.path(), floor);
			let response = jmap(
				dir.path(),
				&app,
				UNSUBSCRIBE,
				&["bob@elsewhere.example"],
				asked.as_str(),
			)
			.await;
			let id = response["created"]["s1"]["id"]
				.as_str()
				.unwrap_or_else(|| panic!("{floor} / {asked}: {response}"));
			let entry = FsSpool::open(dir.path())
				.expect("spool")
				.load(uuid::Uuid::parse_str(id).expect("uuid"))
				.expect("queued");
			assert_eq!(
				entry.envelope.class,
				stricter(floor, asked),
				"bound to {floor}, the request asks {asked}"
			);
		}
	}
}
