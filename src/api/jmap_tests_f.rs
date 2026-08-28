//! JMAP method-level scope enforcement (RFC 8620 §3.6.2).

use super::router;
use super::tests::{request_with_body, test_state};
use axum::Router;

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
