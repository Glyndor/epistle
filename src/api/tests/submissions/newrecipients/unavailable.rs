//! A cap that cannot be checked is not skipped: while the correspondent store
//! fails, a submission under a configured cap is refused with a temporary
//! error and nothing is queued, and the cap works again once the store does.
//! Without a cap the store only keeps a record, and a failure there does not
//! stop the message.

use super::*;
use serde_json::{Value, json};

/// Put a file where the store's directory is, so that taking its lock fails
/// while the rest of the data directory is untouched.
fn break_store(dir: &std::path::Path) {
	std::fs::rename(dir.join("correspondents"), dir.join("correspondents.away")).expect("move");
	std::fs::write(dir.join("correspondents"), b"").expect("file in its place");
}

fn repair_store(dir: &std::path::Path) {
	std::fs::remove_file(dir.join("correspondents")).expect("remove the file");
	std::fs::rename(dir.join("correspondents.away"), dir.join("correspondents"))
		.expect("move back");
}

const THREE: [&str; 3] = [
	"b@elsewhere.example",
	"c@elsewhere.example",
	"d@elsewhere.example",
];

async fn rest_send(app: &axum::Router) -> (StatusCode, Value) {
	rest(app, false).await
}

/// `POST /api/v1/send` to the three recipients, as a dry run or not.
async fn rest(app: &axum::Router, dry_run: bool) -> (StatusCode, Value) {
	request_with_body(
		app,
		"POST",
		"/api/v1/send",
		Some(TOKEN.as_str()),
		Some(json!({
			"from": "alice@example.org", "to": THREE, "subject": "hi", "text": "body",
			"dry_run": dry_run
		})),
	)
	.await
}

/// A draft to the three recipients, submitted; the response to the
/// submission.
async fn jmap_submit(app: &axum::Router, dir: &std::path::Path) -> Value {
	let inbox = dir.join("accounts/alice/new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		format!(
			"From: alice@example.org\r\nTo: {}\r\nSubject: hello\r\n\r\nbody\r\n",
			THREE.join(", ")
		),
	)
	.expect("write");
	let rcpt: Vec<Value> = THREE.iter().map(|r| json!({"email": r})).collect();
	let (status, body) = request_with_body(
		app,
		"POST",
		"/jmap/api",
		Some(TOKEN.as_str()),
		Some(json!({
			"using": ["urn:ietf:params:jmap:submission"],
			"methodCalls": [["EmailSubmission/set", {
				"accountId": "alice", "create": {"s1": {
					"emailId": id.to_string(),
					"envelope": {"mailFrom": {"email": "alice@example.org"}, "rcptTo": rcpt},
				}},
			}, "c1"]],
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	body["methodResponses"][0][1].clone()
}

fn queued(dir: &std::path::Path) -> usize {
	FsSpool::open(dir)
		.expect("spool")
		.list()
		.expect("list")
		.len()
}

#[tokio::test]
async fn rest_refuses_while_the_cap_cannot_be_checked() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state_with_cap(dir.path(), Some(2)));
	break_store(dir.path());
	let (status, body) = rest_send(&app).await;
	assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
	assert_eq!(body["error"]["code"], "unavailable", "{body}");
	assert!(!body.to_string().contains("correspondents"), "{body}");
	assert_eq!(queued(dir.path()), 0, "nothing was queued");
	repair_store(dir.path());
	let (status, body) = rest_send(&app).await;
	assert_eq!(
		status,
		StatusCode::TOO_MANY_REQUESTS,
		"the cap works again: {body}"
	);
}

/// A dry run asks the cap too, so it answers what the real send would: the
/// same refusal while the cap cannot be checked, and the limit once it can.
#[tokio::test]
async fn a_dry_run_is_refused_while_the_cap_cannot_be_checked() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state_with_cap(dir.path(), Some(2)));
	break_store(dir.path());
	let (status, body) = rest(&app, true).await;
	assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
	assert_eq!(body["error"]["code"], "unavailable", "{body}");
	assert!(!body.to_string().contains("correspondents"), "{body}");
	assert_eq!(rest_send(&app).await, (status, body), "as the real send");
	assert_eq!(queued(dir.path()), 0, "nothing was queued");
	repair_store(dir.path());
	let (status, body) = rest(&app, true).await;
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
	assert_eq!(
		body["error"]["message"], "too many new recipients today; retry tomorrow",
		"the cap, not the limit on dry runs: {body}"
	);
}

#[tokio::test]
async fn jmap_refuses_while_the_cap_cannot_be_checked() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state_with_cap(dir.path(), Some(2)));
	break_store(dir.path());
	let response = jmap_submit(&app, dir.path()).await;
	assert_eq!(
		response["notCreated"]["s1"]["type"], "serverUnavailable",
		"{response}"
	);
	assert_eq!(queued(dir.path()), 0, "nothing was queued");
	repair_store(dir.path());
	let response = jmap_submit(&app, dir.path()).await;
	assert_eq!(
		response["notCreated"]["s1"]["type"], "tooManyRecipients",
		"the cap works again: {response}"
	);
}

#[tokio::test]
async fn a_cap_with_no_store_to_check_it_refuses_too() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = super::super::base::test_state(dir.path(), 0).with_new_recipients_per_day(Some(2));
	let app = router(state);
	let (status, body) = rest_send(&app).await;
	assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
	let response = jmap_submit(&app, dir.path()).await;
	assert_eq!(
		response["notCreated"]["s1"]["type"], "serverUnavailable",
		"{response}"
	);
	assert_eq!(queued(dir.path()), 0);
}

#[tokio::test]
async fn without_a_cap_a_failing_store_does_not_stop_the_message() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state_with_cap(dir.path(), None));
	break_store(dir.path());
	let (status, body) = rest(&app, true).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["dry_run"], true, "{body}");
	let (status, body) = rest_send(&app).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let response = jmap_submit(&app, dir.path()).await;
	assert!(response["created"]["s1"]["id"].is_string(), "{response}");
}
