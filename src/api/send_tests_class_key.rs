//! The class bound to an API key is a floor on every way that key submits.

use axum::http::StatusCode;
use serde_json::json;

use super::router;
use super::send_tests_class::state;
use super::tests::request_with_body;
use crate::evidence::MailClass;
use crate::evidence::bindings::{api_key_key_of_token, update};
use crate::storage::FsSpool;

/// A key for alice that may send, with `class` bound to it.
fn bound_key(dir: &std::path::Path, class: MailClass) -> String {
	let secret = crate::test_fixtures::fresh_secret();
	let mut store = crate::api::ApiKeyStore::open(dir).expect("key store");
	store
		.add(crate::api::api_keys::ApiKey {
			label: "notices".to_string(),
			hash: crate::api::api_keys::sha256_hash(&secret),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["send".to_string(), "read".to_string(), "write".to_string()],
			domains: Vec::new(),
			account: Some("alice".to_string()),
		})
		.expect("add key");
	drop(store);
	update(dir, |bindings| {
		bindings
			.credentials
			.insert(api_key_key_of_token(&secret), class);
	})
	.expect("bind");
	secret
}

fn class_of(dir: &std::path::Path, id: &str) -> MailClass {
	FsSpool::open(dir)
		.expect("spool")
		.load(uuid::Uuid::parse_str(id).expect("uuid"))
		.expect("queued")
		.envelope
		.class
}

#[tokio::test]
async fn the_same_key_submits_with_the_same_class_by_rest_and_by_jmap() {
	let dir = tempfile::tempdir().expect("tempdir");
	let key = bound_key(dir.path(), MailClass::Transactional);
	let (state, _) = state(dir.path());
	let app = router(state);
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(key.as_str()),
		Some(json!({
			"from": "alice@example.org", "to": ["bob@elsewhere.example"],
			"subject": "s", "text": "hi", "class": "personal",
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let rest = class_of(dir.path(), body["queued"].as_str().expect("id"));
	assert_eq!(rest, MailClass::Transactional, "REST ignored the key");
	let inbox = dir.path().join("accounts/alice/new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let email = uuid::Uuid::now_v7();
	std::fs::write(
		inbox.join(format!("{email}.eml")),
		"From: alice@example.org\r\nTo: bob@elsewhere.example\r\nSubject: Drafted\r\n\r\nbody\r\n",
	)
	.expect("write draft");
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(key.as_str()),
		Some(json!({
			"using": ["urn:ietf:params:jmap:submission"],
			"methodCalls": [["EmailSubmission/set", {"accountId": "alice", "create": {"s1": {
				"emailId": email.to_string(),
				"envelope": {"mailFrom": {"email": "alice@example.org"},
					"rcptTo": [{"email": "bob@elsewhere.example"}]},
				"epistle:class": "personal",
			}}}, "c1"]],
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let created = &body["methodResponses"][0][1]["created"]["s1"];
	let jmap = class_of(dir.path(), created["id"].as_str().expect("created"));
	assert_eq!(jmap, rest, "JMAP lets the key send below its class");
}
