//! The submission rate limits on `POST /api/v1/send` and JMAP
//! `EmailSubmission/set`: the per-account limit applies here too, on the
//! limiter SMTP charges; a message is charged one unit per recipient only
//! when it is handed on, and a refused one costs nothing.

use std::sync::Arc;

use super::base::{TOKEN, request_with_body, test_state};
use super::router;
use super::state::ApiState;
use crate::antispam::clamd::ClamdHook;
use crate::antispam::clamd::tests::fake::{FakeClamd, eicar};
use crate::antispam::submission_scan::ScanningSink;
use crate::smtp::ratelimit::SendLimiter;
use crate::smtp::submission_budget::RATE_LIMITED;
use crate::storage::{FsSpool, SplitDelivery};
use axum::http::StatusCode;
use serde_json::{Value, json};

fn now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.expect("clock")
		.as_secs()
}

/// `test_state` whose per-account limit is `per_min` on `limiter`.
fn limited(dir: &std::path::Path, limiter: &Arc<SendLimiter>, per_min: u32) -> ApiState {
	test_state(dir, 0).with_submission_limit(Some(Arc::clone(limiter)), Some(per_min))
}

async fn api_send(app: &axum::Router, to: &[&str], text: &str) -> (StatusCode, Value) {
	request_with_body(
		app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(json!({"from": "alice@example.org", "to": to, "subject": "s", "text": text})),
	)
	.await
}

/// Store `raw` as alice's draft and submit it over JMAP; the creation
/// result or the SetError.
async fn jmap_submit(app: &axum::Router, dir: &std::path::Path, raw: &str) -> Value {
	let inbox = dir.join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(inbox.join(format!("{id}.eml")), raw).expect("write draft");
	let call = json!(["EmailSubmission/set",
		{"accountId": "alice", "create": {"s": {"emailId": id.to_string()}}}, "c"]);
	let req = json!({"using": ["urn:ietf:params:jmap:submission"], "methodCalls": [call]});
	let (status, body) =
		request_with_body(app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let response = &body["methodResponses"][0][1];
	match response["created"]["s"].is_object() {
		true => response["created"]["s"].clone(),
		false => response["notCreated"]["s"].clone(),
	}
}

fn draft(to: &str, text: &str) -> String {
	format!("From: alice@example.org\r\nTo: {to}\r\nSubject: s\r\n\r\n{text}\r\n")
}

/// The per-account limit binds REST and JMAP on the limiter SMTP uses: a
/// unit SMTP spent is gone for them, and the refusal is exact.
#[tokio::test]
async fn the_account_limit_is_one_budget_across_smtp_rest_and_jmap() {
	let dir = tempfile::tempdir().expect("tempdir");
	let limiter = Arc::new(SendLimiter::for_authenticated_keys(60));
	assert!(limiter.check("alice", 3, now()), "SMTP spends one unit");
	let app = router(limited(dir.path(), &limiter, 3));
	let (status, body) = api_send(&app, &["bob@elsewhere.example"], "hi").await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let created = jmap_submit(&app, dir.path(), &draft("bob@elsewhere.example", "hi")).await;
	assert!(created["id"].is_string(), "{created}");
	let (status, body) = api_send(&app, &["bob@elsewhere.example"], "hi").await;
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
	assert_eq!(body["error"]["code"], "rate_limited");
	assert_eq!(body["error"]["message"], RATE_LIMITED);
	let refused = jmap_submit(&app, dir.path(), &draft("bob@elsewhere.example", "hi")).await;
	assert_eq!(
		refused,
		json!({"type": "rateLimit", "description": RATE_LIMITED})
	);
}

/// A first send wider than the limit is refused whole, and costs nothing.
#[tokio::test]
async fn a_first_send_wider_than_the_limit_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let limiter = Arc::new(SendLimiter::for_authenticated_keys(60));
	let app = router(limited(dir.path(), &limiter, 2));
	let three = [
		"a@elsewhere.example",
		"b@elsewhere.example",
		"c@elsewhere.example",
	];
	let (status, body) = api_send(&app, &three, "hi").await;
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
	let (status, body) = api_send(&app, &three[..2], "hi").await;
	assert_eq!(status, StatusCode::OK, "{body}");
}

/// A routing sink behind the antivirus scan, with a per-account limit of
/// one recipient a minute.
fn scanned(dir: &std::path::Path, clamd: &FakeClamd) -> ApiState {
	let directory =
		crate::directory_store::DirectoryHandle::new(crate::smtp::directory::Directory::new(
			["example.org".to_string()],
			[("alice@example.org".to_string(), "alice".to_string())],
		));
	let split = SplitDelivery::new(dir, directory).expect("sink");
	let hook = Arc::new(ClamdHook::new(clamd.socket.clone()));
	let sink = ScanningSink::wrap(true, Arc::new(split), Some(hook), None, None).expect("sink");
	let limiter = Arc::new(SendLimiter::for_authenticated_keys(60));
	limited(dir, &limiter, 1).with_outbound(sink)
}

/// A send the outbound path refuses (here the antivirus) gets its units
/// back, on REST and on JMAP.
#[tokio::test]
async fn a_send_refused_on_the_way_out_costs_nothing() {
	let clamd = FakeClamd::start();
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(scanned(dir.path(), &clamd));
	let (status, body) = api_send(&app, &["bob@elsewhere.example"], &eicar()).await;
	assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
	let refused = jmap_submit(&app, dir.path(), &draft("bob@elsewhere.example", &eicar())).await;
	assert_eq!(refused["type"], "forbiddenToSend", "{refused}");
	let (status, body) = api_send(&app, &["bob@elsewhere.example"], "hello").await;
	assert_eq!(
		status,
		StatusCode::OK,
		"the refused sends took nothing: {body}"
	);
	let (status, _) = api_send(&app, &["bob@elsewhere.example"], "hello").await;
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

/// Without an envelope JMAP sends to the deduplicated To, Cc and Bcc
/// (RFC 8621 section 7.5) and is charged for those: an address named twice
/// (its domain in another case) is one recipient, and Resent-* fields of an
/// earlier copy are not sent to.
#[tokio::test]
async fn jmap_sends_to_and_charges_the_deduplicated_to_cc_and_bcc_only() {
	let dir = tempfile::tempdir().expect("tempdir");
	let limiter = Arc::new(SendLimiter::for_authenticated_keys(60));
	let app = router(limited(dir.path(), &limiter, 2));
	let raw = "From: alice@example.org\r\nTo: bob@elsewhere.example\r\n\
		Cc: bob@ELSEWHERE.example, carol@elsewhere.example\r\n\
		Resent-To: earlier@elsewhere.example\r\nResent-Bcc: hidden@elsewhere.example\r\n\
		Subject: s\r\n\r\nhi\r\n";
	let created = jmap_submit(&app, dir.path(), raw).await;
	assert!(
		created["id"].is_string(),
		"two recipients fit a limit of two: {created}"
	);
	let spool = FsSpool::open(dir.path()).expect("spool");
	let entry = spool.load(spool.list().expect("list")[0]).expect("entry");
	assert_eq!(
		entry.envelope.recipients,
		["bob@elsewhere.example", "carol@elsewhere.example"]
	);
	let refused = jmap_submit(&app, dir.path(), &draft("dave@elsewhere.example", "hi")).await;
	assert_eq!(refused["type"], "rateLimit", "{refused}");
}
