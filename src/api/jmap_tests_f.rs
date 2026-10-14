//! JMAP method-level scope enforcement (RFC 8620 §3.6.2).

use super::router;
use super::tests::{request_with_body, test_state};
use axum::Router;
use std::sync::Arc;

/// Attach a scoped API key to a fresh state and return the bearer secret and
/// the `Router`. Centralised here so the three JMAP-scope tests below stay
/// one line each.
fn state_with_scoped_key(dir: &tempfile::TempDir, scopes: &[&str]) -> (Router, String) {
	let mut key_store = crate::api::ApiKeyStore::open(dir.path()).expect("open key store");
	let secret = format!("scoped-secret-{}", scopes.join("-"));
	key_store
		.add(crate::api::api_keys::ApiKey {
			label: "scoped".to_string(),
			hash: crate::api::api_keys::sha256_hash(&secret),
			expires_at: None,
			ip_cidr: None,
			scopes: scopes.iter().map(|s| s.to_string()).collect(),
			domains: Vec::new(),
			account: None,
		})
		.expect("add key");
	drop(key_store);
	let app = router(test_state(dir.path(), 0));
	(app, secret)
}
use axum::http::StatusCode;

// --- JMAP method-level scope enforcement ----------------------------------------

/// A read-only API key hitting `Mailbox/set` must be rejected with `forbidden`
/// (RFC 8620 §3.6.2). The middleware's coarse path/method inference would let
/// any authenticated `POST /jmap/api` through as `Read`; the dispatcher's
/// per-method check is what stops the read-only key from creating a mailbox.
#[tokio::test]
async fn jmap_mailbox_set_rejects_read_scoped_key() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = state_with_scoped_key(&dir, &["read"]);
	let req = serde_json::json!({
		"methodCalls": [["Mailbox/set", {"accountId": "alice", "create": {"c": {"name": "Saved"}}}, "m1"]],
	});
	let (status, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(&secret), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let response = &body["methodResponses"][0];
	assert_eq!(
		response[1]["type"], "forbidden",
		"read-only key must not create a mailbox: {body}"
	);
}

/// A write-scoped API key can create a mailbox: the acceptance half of the
/// JMAP write control.
#[tokio::test]
async fn jmap_mailbox_set_admits_write_scoped_key() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (app, secret) = state_with_scoped_key(&dir, &["write"]);
	let req = serde_json::json!({
		"methodCalls": [["Mailbox/set", {"accountId": "alice", "create": {"c": {"name": "Saved"}}}, "m1"]],
	});
	let (status, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(&secret), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let response = &body["methodResponses"][0];
	// A forbidden rejection would arrive as the JMAP error type; a success
	// response carries a `created` map.
	assert_eq!(
		response[1]["created"]["c"]["id"], "Saved",
		"write-scoped key must create a mailbox: {body}"
	);
}

/// A write-scoped key (no `Send`) is still rejected on `EmailSubmission/set`:
/// each scope is independent, so a write-only key cannot originate outbound
/// mail.
#[tokio::test]
async fn jmap_email_submission_rejects_write_only_key() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		b"From: alice@example.org\r\nTo: bob@elsewhere.example\r\nSubject: hi\r\n\r\nbody\r\n",
	)
	.expect("write");
	let (app, secret) = state_with_scoped_key(&dir, &["write"]);
	let req = serde_json::json!({
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
		request_with_body(&app, "POST", "/jmap/api", Some(&secret), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let response = &body["methodResponses"][0];
	assert_eq!(
		response[1]["type"], "forbidden",
		"write-only key must not submit outbound mail: {body}"
	);
}

// --- per-tenant submission limit + recipient cap on EmailSubmission/set ----

/// Build an `ApiState` whose `TenantLimits` declare
/// `submission_rate_limit_per_min = per_min` on the example.org
/// tenant. The shared SendLimiter on REST, SMTP and JMAP is the
/// one the operator would configure in production; the test mirrors
/// that to assert the cap is shared across protocols.
fn tenant_state(dir: &std::path::Path, per_min: u32) -> super::ApiState {
	let mut state = test_state(dir, 0);
	let limits = Arc::new(crate::api::TenantLimits::from_config(&[
		crate::config::Tenant {
			name: Some("acme".to_string()),
			domains: vec!["example.org".to_string()],
			quota_bytes: None,
			max_accounts: None,
			max_domains: None,
			submission_rate_limit_per_min: Some(per_min),
		},
	]));
	state = state.with_tenant_limits(Arc::clone(&limits));
	state
}

/// Seed the alice mailbox with a stored email whose body lists every
/// recipient. Used by the JMAP rate-limit and recipient-cap tests so
/// the envelope-only `rcptTo` and the body header `To` agree.
fn seed_email(dir: &std::path::Path, recipients: &[String]) -> uuid::Uuid {
	let path = dir.join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&path).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	let mut body = String::from("From: alice@example.org\r\n");
	body.push_str(&format!("To: {}\r\n", recipients.join(", ")));
	body.push_str("Subject: hello\r\n\r\nbody\r\n");
	std::fs::write(path.join(format!("{id}.eml")), body.as_bytes()).expect("write");
	id
}

/// Seed a message that exercises every header the rate-limit
/// counter sums: To, Cc, Bcc, Resent-To, Resent-Cc, Resent-Bcc,
/// plus an envelope-only recipient that is in no header. The cap is
/// one unit per recipient.
fn seed_email_with_all_kinds(dir: &std::path::Path, headers: &[(&str, &str)]) -> uuid::Uuid {
	let path = dir.join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&path).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	let mut body = String::from("From: alice@example.org\r\n");
	for (header, value) in headers {
		body.push_str(&format!("{header}: {value}\r\n"));
	}
	body.push_str("Subject: hello\r\n\r\nbody\r\n");
	std::fs::write(path.join(format!("{id}.eml")), body.as_bytes()).expect("write");
	id
}

fn submission_request(email_id: &uuid::Uuid, rcpt_to: &[String]) -> serde_json::Value {
	let rcpts: Vec<serde_json::Value> = rcpt_to
		.iter()
		.map(|email| serde_json::json!({"email": email}))
		.collect();
	serde_json::json!({
		"methodCalls": [["EmailSubmission/set", {
			"accountId": "alice",
			"create": { "s1": {
				"emailId": email_id.to_string(),
				"identityId": "alice@example.org",
				"envelope": {"mailFrom": {"email": "alice@example.org"}, "rcptTo": rcpts},
			} },
		}, "c1"]],
	})
}

/// The JMAP recipient cap mirrors the SMTP and REST `MAX_RECIPIENTS`
/// ceiling (RFC 9422). A submission whose envelope has 101 recipients
/// is refused with the `tooManyRecipients` SetError, the same wording
/// used for the rolling 24h new-recipient cap so an operator reading
/// either log can correlate the two.
#[tokio::test]
async fn jmap_email_submission_caps_recipients_at_max() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let rcpts: Vec<String> = (0..crate::smtp::session::MAX_RECIPIENTS + 1)
		.map(|i| format!("r{i}@elsewhere.example"))
		.collect();
	let email_id = seed_email(dir.path(), &rcpts);
	let req = submission_request(&email_id, &rcpts);
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(super::tests::TOKEN.as_str()),
		Some(req),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let response = &body["methodResponses"][0];
	assert_eq!(
		response[1]["notCreated"]["s1"]["type"], "tooManyRecipients",
		"envelope with more than MAX_RECIPIENTS must be refused: {body}"
	);
}

/// The per-tenant aggregate submission rate limit applies to JMAP
/// exactly the same way it applies to SMTP and REST, because the
/// three protocols consult the same `Arc<SendLimiter>`. A sender
/// behind a tenant cap cannot triple the budget by switching
/// protocols. The on-wire error is `rateLimit` (RFC 8620 §5.3's
/// resource-cap reply, the closest match to "your tenant is at its
/// per-minute cap"). With `submission_rate_limit_per_min = 1` the
/// second submission in the same window is refused.
#[tokio::test]
async fn jmap_email_submission_refuses_over_the_tenant_cap() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(tenant_state(dir.path(), 1));
	let rcpts = vec!["bob@elsewhere.example".to_string()];
	// First submission fits: count goes from 0 to 1, within the cap of 1.
	let email_id = seed_email(dir.path(), &rcpts);
	let req = submission_request(&email_id, &rcpts);
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(super::tests::TOKEN.as_str()),
		Some(req),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert!(
		body["methodResponses"][0]["notCreated"]["s1"].is_null(),
		"first submission must be accepted: {body}"
	);
	// Second submission is over the tenant cap.
	let email_id = seed_email(dir.path(), &rcpts);
	let req = submission_request(&email_id, &rcpts);
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(super::tests::TOKEN.as_str()),
		Some(req),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let response = &body["methodResponses"][0];
	assert_eq!(
		response[1]["notCreated"]["s1"]["type"], "rateLimit",
		"second submission must be refused by the tenant cap: {body}"
	);
}

/// The shared limiter means a sender who already exhausted the tenant
/// budget over SMTP cannot send a fresh JMAP submission to lift it:
/// the JMAP path sees the same `SendLimiter` key, so the cap is
/// enforced uniformly. With the tenant cap at 1, two consecutive
/// JMAP submissions from the same tenant exhaust it; the second
/// one is refused with `rateLimit`.
#[tokio::test]
async fn jmap_email_submission_refuses_when_smtp_already_charged() {
	use crate::api::TenantLimits;
	let dir = tempfile::tempdir().expect("tempdir");
	let limits = Arc::new(TenantLimits::from_config(&[crate::config::Tenant {
		name: Some("acme".to_string()),
		domains: vec!["example.org".to_string()],
		quota_bytes: None,
		max_accounts: None,
		max_domains: None,
		submission_rate_limit_per_min: Some(1),
	}]));
	let mut state = test_state(dir.path(), 0);
	state = state.with_tenant_limits(Arc::clone(&limits));
	let app = router(state);
	let rcpts = vec!["bob@elsewhere.example".to_string()];
	// First submission exhausts the cap.
	let email_id = seed_email(dir.path(), &rcpts);
	let req = submission_request(&email_id, &rcpts);
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(super::tests::TOKEN.as_str()),
		Some(req),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert!(
		body["methodResponses"][0]["notCreated"]["s1"].is_null(),
		"first submission must be accepted: {body}"
	);
	// Seed a fresh email; the limiter's count is 1 already, so the
	// next submission must also refuse on the same key.
	let email_id = seed_email(dir.path(), &rcpts);
	let req = submission_request(&email_id, &rcpts);
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(super::tests::TOKEN.as_str()),
		Some(req),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(
		body["methodResponses"][0][1]["notCreated"]["s1"]["type"], "rateLimit",
		"{body}"
	);
}

/// Per-recipient counting on the tenant cap: a single submission to
/// many recipients costs one unit per recipient, so a tenant cap of
/// 2 is exhausted by one message to two recipients. The next
/// submission is refused with `rateLimit`, proving the charge
/// matched the recipient count and not the message count.
#[tokio::test]
async fn jmap_email_submission_tenant_cap_charges_per_recipient() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(tenant_state(dir.path(), 2));
	let rcpts = vec![
		"r1@elsewhere.example".to_string(),
		"r2@elsewhere.example".to_string(),
	];
	// One submission with two recipients costs 2 units.
	let email_id = seed_email(dir.path(), &rcpts);
	let req = submission_request(&email_id, &rcpts);
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(super::tests::TOKEN.as_str()),
		Some(req),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert!(
		body["methodResponses"][0]["notCreated"]["s1"].is_null(),
		"first two-recipient submission must be accepted: {body}"
	);
	// One submission with one recipient must be over the cap.
	let rcpts_one = vec!["r3@elsewhere.example".to_string()];
	let email_id = seed_email(dir.path(), &rcpts_one);
	let req = submission_request(&email_id, &rcpts_one);
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(super::tests::TOKEN.as_str()),
		Some(req),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(
		body["methodResponses"][0][1]["notCreated"]["s1"]["type"], "rateLimit",
		"second submission must be deferred when the per-tenant budget is exhausted by recipient count: {body}"
	);
}

/// The recipient count covers every kind of recipient the protocol
/// can carry: To, Cc, Bcc, Resent-To, Resent-Cc, Resent-Bcc, and an
/// envelope-only recipient that is in no header. With the tenant cap
/// at 6, the first message is admitted (6 units = 6 recipients); the
/// second message is over the cap.
#[tokio::test]
async fn jmap_email_submission_charges_every_kind_of_recipient() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(tenant_state(dir.path(), 6));
	let headers = [
		("To", "to@elsewhere.example"),
		("Cc", "cc@elsewhere.example"),
		("Bcc", "bcc@elsewhere.example"),
		("Resent-To", "resent-to@elsewhere.example"),
		("Resent-Cc", "resent-cc@elsewhere.example"),
		("Resent-Bcc", "resent-bcc@elsewhere.example"),
	];
	let email_id = seed_email_with_all_kinds(dir.path(), &headers);
	let rcpts: Vec<String> = headers.iter().map(|(_, email)| email.to_string()).collect();
	let req = submission_request(&email_id, &rcpts);
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(super::tests::TOKEN.as_str()),
		Some(req),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert!(
		body["methodResponses"][0]["notCreated"]["s1"].is_null(),
		"six-recipient message must be accepted at the cap of 6: {body}"
	);
	// A second one-recipient message is over the cap.
	let rcpts_one = vec!["r7@elsewhere.example".to_string()];
	let email_id = seed_email(dir.path(), &rcpts_one);
	let req = submission_request(&email_id, &rcpts_one);
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(super::tests::TOKEN.as_str()),
		Some(req),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(
		body["methodResponses"][0][1]["notCreated"]["s1"]["type"], "rateLimit",
		"second message must be over the cap when every recipient kind is counted: {body}"
	);
}
