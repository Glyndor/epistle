//! JMAP endpoint tests (RFC 8620/8621).

use super::router;
use super::tests::{TOKEN, request, request_with_body, test_state};
use axum::Router;

/// Attach a scoped API key to a fresh state and return the bearer secret and
/// the `Router`. Centralised here so the four JMAP-scope tests below stay
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
		})
		.expect("add key");
	drop(key_store);
	let app = router(test_state(dir.path(), 0));
	(app, secret)
}
use axum::http::StatusCode;

#[tokio::test]
async fn jmap_session_advertises_core_capability() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, body) = request(&app, "GET", "/jmap/session", Some(TOKEN)).await;
	assert_eq!(status, StatusCode::OK);
	assert!(
		body["capabilities"]["urn:ietf:params:jmap:core"].is_object(),
		"{body}"
	);
	assert_eq!(body["apiUrl"], "/jmap/api");
	assert!(body["accounts"]["alice"].is_object(), "{body}");
	// Auth is required.
	let (status, _) = request(&app, "GET", "/jmap/session", None).await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jmap_well_known_serves_session() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	// RFC 8620 §2.2 autodiscovery path returns the Session resource.
	let (status, body) = request(&app, "GET", "/.well-known/jmap", Some(TOKEN)).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["apiUrl"], "/jmap/api");
	assert!(
		body["capabilities"]["urn:ietf:params:jmap:core"].is_object(),
		"{body}"
	);
}

#[tokio::test]
async fn jmap_core_echo_round_trips() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:core"],
		"methodCalls": [["Core/echo", {"hello": "world"}, "c1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["methodResponses"][0][0], "Core/echo");
	assert_eq!(body["methodResponses"][0][1]["hello"], "world");
	assert_eq!(body["methodResponses"][0][2], "c1");

	let req = serde_json::json!({
		"using": [],
		"methodCalls": [["Widget/get", {}, "c2"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(body["methodResponses"][0][0], "error");
	assert_eq!(body["methodResponses"][0][1]["type"], "unknownMethod");
}

#[tokio::test]
async fn jmap_mailbox_set_creates_and_destroys() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));

	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Mailbox/set", {
			"accountId": "alice",
			"create": { "c1": {"name": "Work", "parentId": null} },
		}, "m1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["methodResponses"][0][1]["created"]["c1"]["id"], "Work");

	let req = serde_json::json!({
		"methodCalls": [["Mailbox/get", {"accountId": "alice"}, "m2"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	let names: Vec<_> = body["methodResponses"][0][1]["list"]
		.as_array()
		.expect("list")
		.iter()
		.map(|m| m["name"].as_str().unwrap_or("").to_string())
		.collect();
	assert!(names.contains(&"Work".to_string()), "{names:?}");

	let req = serde_json::json!({
		"methodCalls": [["Mailbox/set", {"accountId": "alice", "destroy": ["Work"]}, "m3"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(body["methodResponses"][0][1]["destroyed"][0], "Work");
}

#[tokio::test]
async fn jmap_mailbox_query_lists_ids() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let req = serde_json::json!({
		"methodCalls": [["Mailbox/set", {"accountId": "alice", "create": {"c": {"name": "Work"}}}, "m1"]],
	});
	request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Mailbox/query", {"accountId": "alice"}, "q1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	let ids = body["methodResponses"][0][1]["ids"].to_string();
	assert!(ids.contains("INBOX") && ids.contains("Work"), "{ids}");
	assert_eq!(body["methodResponses"][0][1]["total"], 2);

	// Unknown account is reported, not a 500.
	let req = serde_json::json!({
		"methodCalls": [["Mailbox/query", {"accountId": "nobody"}, "q2"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(body["methodResponses"][0][1]["type"], "accountNotFound");
}

#[tokio::test]
async fn jmap_mailbox_get_lists_inbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	std::fs::write(inbox.join(format!("{}.eml", uuid::Uuid::now_v7())), b"x").expect("write");

	let app = router(test_state(dir.path(), 0));
	let (_, session) = request(&app, "GET", "/jmap/session", Some(TOKEN)).await;
	assert!(
		session["capabilities"]["urn:ietf:params:jmap:mail"].is_object(),
		"{session}"
	);

	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Mailbox/get", {"accountId": "alice", "ids": null}, "c1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	let response = &body["methodResponses"][0];
	assert_eq!(response[0], "Mailbox/get");
	let inbox = &response[1]["list"][0];
	assert_eq!(inbox["name"], "INBOX");
	assert_eq!(inbox["role"], "inbox");
	assert_eq!(inbox["totalEmails"], 1);

	// An unknown account is reported, not a 500.
	let req = serde_json::json!({
		"methodCalls": [["Mailbox/get", {"accountId": "nobody"}, "c2"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(body["methodResponses"][0][0], "error");
	assert_eq!(body["methodResponses"][0][1]["type"], "accountNotFound");
}

#[tokio::test]
async fn jmap_email_submission_queues_message() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
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
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	assert!(
		body["methodResponses"][0][1]["created"]["s1"]["id"].is_string(),
		"{body}"
	);
	let spool_new = dir.path().join("spool").join("new");
	let count = std::fs::read_dir(&spool_new)
		.map(|d| d.count())
		.unwrap_or(0);
	assert!(count >= 1, "expected a spooled message");
}

/// `EmailSubmission/set` must reject a non-empty `envelope.mailFrom.email`
/// that the named `accountId` does not own. Without this guard a bearer
/// token holder can submit outbound mail as any address (RFC 8621 §7.5.2:
/// `forbiddenFrom`).
#[tokio::test]
async fn jmap_email_submission_rejects_unowned_mail_from() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		b"From: alice@example.org\r\nTo: bob@elsewhere.example\r\nSubject: hi\r\n\r\nbody\r\n",
	)
	.expect("write");
	let app = router(test_state(dir.path(), 0));

	// alice tries to send as bob@elsewhere.example — an address no one owns
	// in this test's directory (only alice@example.org is configured).
	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:submission"],
		"methodCalls": [["EmailSubmission/set", {
			"accountId": "alice",
			"create": { "s1": {
				"emailId": id.to_string(),
				"identityId": "alice@example.org",
				"envelope": {"mailFrom": {"email": "bob@elsewhere.example"},
					"rcptTo": [{"email": "carol@elsewhere.example"}]},
			} },
		}, "c1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let response = &body["methodResponses"][0];
	assert_eq!(
		response[1]["notCreated"]["s1"]["type"],
		"forbiddenFrom",
		"send-as must be rejected with forbiddenFrom: {body}"
	);
}

/// `EmailSubmission/set` must reject a `mailFrom` that does not parse as an
/// address: a malformed envelope value is not a free pass to spoofing.
#[tokio::test]
async fn jmap_email_submission_rejects_malformed_mail_from() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
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
				"envelope": {"mailFrom": {"email": "not-an-address"},
					"rcptTo": [{"email": "bob@elsewhere.example"}]},
			} },
		}, "c1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let response = &body["methodResponses"][0];
	assert_eq!(
		response[1]["notCreated"]["s1"]["type"],
		"invalidEmail",
		"malformed mailFrom must be rejected with invalidEmail: {body}"
	);
}

/// `EmailSubmission/set` must accept a `mailFrom` that is one of the
/// account's configured addresses — the acceptance case that proves the
/// control does not over-reject (paired with the two rejection tests above).
#[tokio::test]
async fn jmap_email_submission_accepts_owned_mail_from() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		b"From: alice@example.org\r\nTo: bob@elsewhere.example\r\nSubject: hi\r\n\r\nbody\r\n",
	)
	.expect("write");
	let app = router(test_state(dir.path(), 0));

	// The case-insensitive variant `ALICE@EXAMPLE.ORG` still matches:
	// `Directory::owns_address` lower-cases the key (smtp/directory.rs:412).
	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:submission"],
		"methodCalls": [["EmailSubmission/set", {
			"accountId": "alice",
			"create": { "s1": {
				"emailId": id.to_string(),
				"identityId": "alice@example.org",
				"envelope": {"mailFrom": {"email": "ALICE@EXAMPLE.ORG"},
					"rcptTo": [{"email": "bob@elsewhere.example"}]},
			} },
		}, "c1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert!(
		body["methodResponses"][0][1]["created"]["s1"]["id"].is_string(),
		"owned mailFrom (case-insensitive) must be accepted: {body}"
	);
}

#[tokio::test]
async fn jmap_quota_get_reports_usage() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	std::fs::write(
		inbox.join(format!("{}.eml", uuid::Uuid::now_v7())),
		b"hello",
	)
	.expect("write");
	let app = router(test_state(dir.path(), 0).with_quota(1_000_000));
	let (_, session) = request(&app, "GET", "/jmap/session", Some(TOKEN)).await;
	assert!(
		session["capabilities"]["urn:ietf:params:jmap:quota"].is_object(),
		"{session}"
	);
	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:quota"],
		"methodCalls": [["Quota/get", {"accountId": "alice"}, "c1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	let quota = &body["methodResponses"][0][1]["list"][0];
	assert_eq!(quota["limit"], 1_000_000);
	assert!(quota["used"].as_u64().expect("used") >= 5, "{quota}");
}

#[tokio::test]
async fn jmap_identity_get_lists_addresses() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (_, session) = request(&app, "GET", "/jmap/session", Some(TOKEN)).await;
	assert!(
		session["capabilities"]["urn:ietf:params:jmap:submission"].is_object(),
		"{session}"
	);
	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:submission"],
		"methodCalls": [["Identity/get", {"accountId": "alice"}, "c1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	let identity = &body["methodResponses"][0][1]["list"][0];
	assert_eq!(identity["email"], "alice@example.org");
	assert_eq!(identity["name"], "alice");
}

#[tokio::test]
async fn jmap_email_copy_duplicates_to_mailbox() {
	let dir = tempfile::tempdir().expect("tempdir");
	let inbox = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{id}.eml")),
		b"Subject: x\r\n\r\nbody\r\n",
	)
	.expect("write");
	let app = router(test_state(dir.path(), 0));
	let req = serde_json::json!({
		"methodCalls": [["Mailbox/set", {"accountId": "alice", "create": {"c": {"name": "Saved"}}}, "m1"]],
	});
	request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;

	let req = serde_json::json!({
		"methodCalls": [["Email/copy", {
			"accountId": "alice", "fromAccountId": "alice",
			"create": { "k": {"emailId": id.to_string(), "mailboxIds": {"Saved": true}} },
		}, "c1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	assert!(
		body["methodResponses"][0][1]["created"]["k"]["id"].is_string(),
		"{body}"
	);
	let req = serde_json::json!({
		"methodCalls": [
			["Email/query", {"accountId": "alice", "filter": {"inMailbox": "INBOX"}}, "q1"],
			["Email/query", {"accountId": "alice", "filter": {"inMailbox": "Saved"}}, "q2"],
		],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(body["methodResponses"][0][1]["total"], 1);
	assert_eq!(body["methodResponses"][1][1]["total"], 1);
}

#[tokio::test]
async fn jmap_mailbox_set_update_create_invalid_and_destroy_unknown() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));

	// Create a folder to rename.
	let req = serde_json::json!({
		"methodCalls": [["Mailbox/set", {"accountId": "alice", "create": {"c": {"name": "Work"}}}, "m1"]],
	});
	request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;

	let req = serde_json::json!({
		"methodCalls": [["Mailbox/set", {
			"accountId": "alice",
			"create": { "bad": {} },
			"update": { "Work": {"name": "Projects"}, "Ghost": {"name": "X"} },
			"destroy": ["Nonexistent"],
		}, "m2"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	let r = &body["methodResponses"][0][1];
	// A create without a name is rejected.
	assert_eq!(
		r["notCreated"]["bad"]["type"], "invalidProperties",
		"{body}"
	);
	// Renaming the real folder succeeds; the unknown one is rejected.
	assert!(r["updated"].get("Work").is_some(), "{body}");
	assert_eq!(
		r["notUpdated"]["Ghost"]["type"], "invalidProperties",
		"{body}"
	);
	// Destroying a missing mailbox reports notFound.
	assert_eq!(
		r["notDestroyed"]["Nonexistent"]["type"], "notFound",
		"{body}"
	);
}

#[tokio::test]
async fn jmap_mailbox_get_filters_by_ids() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let req = serde_json::json!({
		"methodCalls": [["Mailbox/set", {"accountId": "alice", "create": {"c": {"name": "Work"}}}, "m1"]],
	});
	request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;

	// Request only INBOX by id: Work is filtered out.
	let req = serde_json::json!({
		"methodCalls": [["Mailbox/get", {"accountId": "alice", "ids": ["INBOX"]}, "m2"]],
	});
	let (_, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	let names: Vec<String> = body["methodResponses"][0][1]["list"]
		.as_array()
		.expect("list")
		.iter()
		.map(|m| m["name"].as_str().unwrap_or("").to_string())
		.collect();
	assert_eq!(names, vec!["INBOX".to_string()], "{body}");
}

#[tokio::test]
async fn jmap_query_changes_reports_cannot_calculate() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Email/queryChanges", {"accountId": "alice", "sinceQueryState": "0"}, "c1"]],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["methodResponses"][0][0], "error");
	assert_eq!(
		body["methodResponses"][0][1]["type"],
		"cannotCalculateChanges"
	);
}

#[tokio::test]
async fn jmap_result_back_reference_chains_calls() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let app = router(test_state(dir.path(), 0));
	// Mailbox/query then Mailbox/get the resulting ids via a back-reference.
	let req = serde_json::json!({
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [
			["Mailbox/query", {"accountId": "alice"}, "q1"],
			["Mailbox/get", {
				"accountId": "alice",
				"#ids": {"resultOf": "q1", "name": "Mailbox/query", "path": "/ids"}
			}, "g1"]
		],
	});
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(TOKEN), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["methodResponses"][1][0], "Mailbox/get");
	// The INBOX resolved from the query's ids is present in the get result.
	let list = body["methodResponses"][1][1]["list"].to_string();
	assert!(list.contains("INBOX"), "{list}");
}

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
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(&secret), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let response = &body["methodResponses"][0];
	assert_eq!(
		response[1]["type"],
		"forbidden",
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
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(&secret), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let response = &body["methodResponses"][0];
	// A forbidden rejection would arrive as the JMAP error type; a success
	// response carries a `created` map.
	assert_eq!(
		response[1]["created"]["c"]["id"],
		"Saved",
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
	let (status, body) = request_with_body(&app, "POST", "/jmap/api", Some(&secret), Some(req)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let response = &body["methodResponses"][0];
	assert_eq!(
		response[1]["type"],
		"forbidden",
		"write-only key must not submit outbound mail: {body}"
	);
}
