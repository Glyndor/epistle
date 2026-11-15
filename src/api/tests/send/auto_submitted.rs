//! The per-key `Auto-Submitted` default of `POST /api/v1/send`: written when
//! the request omits the header and the key has the setting, never over a
//! value the request gave, never for another credential or send path.

use super::base::{TOKEN, request_with_body};
use super::router;
use super::send_outbound::routed_state;
use crate::dkim::test_support::signature_headers;
use crate::storage::FsSpool;
use axum::http::StatusCode;
use serde_json::{Value, json};

/// A key for alice that may send, with the setting as given.
fn add_key(dir: &std::path::Path, auto_submitted: bool) -> String {
	let secret = crate::test_support::fixtures::fresh_secret();
	let mut store = crate::api::ApiKeyStore::open(dir).expect("key store");
	store
		.add(crate::api::api_keys::ApiKey {
			label: "apps".to_string(),
			hash: crate::api::api_keys::sha256_hash(&secret),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["send".to_string(), "read".to_string(), "write".to_string()],
			domains: Vec::new(),
			account: Some("alice".to_string()),
			auto_submitted,
		})
		.expect("add key");
	secret
}

async fn send(app: &axum::Router, secret: &str, extra: Value) -> (StatusCode, Value) {
	let mut body = json!({
		"from": "alice@example.org", "to": ["bob@elsewhere.example"],
		"subject": "s", "text": "hi",
	});
	for (key, value) in extra.as_object().expect("object") {
		body[key] = value.clone();
	}
	request_with_body(app, "POST", "/api/v1/send", Some(secret), Some(body)).await
}

/// The queued message under `id`.
fn queued(dir: &std::path::Path, id: &str) -> Vec<u8> {
	FsSpool::open(dir)
		.expect("spool")
		.load(uuid::Uuid::parse_str(id).expect("uuid"))
		.expect("queued")
		.data
}

/// Every `Auto-Submitted` field in the message's own header block.
fn auto_submitted(data: &[u8]) -> Vec<String> {
	let text = String::from_utf8(data.to_vec()).expect("utf8");
	let (head, _) = text.split_once("\r\n\r\n").expect("header block");
	head.split("\r\n")
		.filter(|line| line.to_ascii_lowercase().starts_with("auto-submitted:"))
		.map(str::to_string)
		.collect()
}

async fn sent_data(
	dir: &std::path::Path,
	app: &axum::Router,
	secret: &str,
	extra: Value,
) -> Vec<u8> {
	let (status, body) = send(app, secret, extra).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	queued(dir, body["queued"].as_str().expect("id"))
}

#[tokio::test]
async fn enabled_key_adds_auto_submitted_when_request_omits_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let secret = add_key(dir.path(), true);
	let app = router(routed_state(dir.path()));
	let data = sent_data(dir.path(), &app, &secret, json!({})).await;
	assert_eq!(
		auto_submitted(&data),
		vec!["Auto-Submitted: auto-generated".to_string()]
	);
}

#[tokio::test]
async fn enabled_key_keeps_the_request_auto_submitted_value() {
	let dir = tempfile::tempdir().expect("tempdir");
	let secret = add_key(dir.path(), true);
	let app = router(routed_state(dir.path()));
	for (given, written) in [
		("auto-replied", "auto-replied"),
		("no", "no"),
		("Auto-Notified", "auto-notified"),
	] {
		let data = sent_data(dir.path(), &app, &secret, json!({"auto_submitted": given})).await;
		assert_eq!(
			auto_submitted(&data),
			vec![format!("Auto-Submitted: {written}")],
			"request value {given:?}"
		);
	}
}

#[tokio::test]
async fn disabled_key_does_not_add_auto_submitted() {
	let dir = tempfile::tempdir().expect("tempdir");
	let secret = add_key(dir.path(), false);
	let app = router(routed_state(dir.path()));
	let data = sent_data(dir.path(), &app, &secret, json!({})).await;
	assert_eq!(auto_submitted(&data), Vec::<String>::new());
}

/// A key written before the setting existed has no field at all.
#[tokio::test]
async fn legacy_key_without_the_setting_does_not_add_auto_submitted() {
	let dir = tempfile::tempdir().expect("tempdir");
	let secret = crate::test_support::fixtures::fresh_secret();
	std::fs::write(
		dir.path().join("api_keys.toml"),
		format!(
			"[[keys]]\nlabel = \"old\"\nhash = \"{}\"\nscopes = [\"send\"]\naccount = \"alice\"\n",
			crate::api::api_keys::sha256_hash(&secret)
		),
	)
	.expect("write keys");
	let app = router(routed_state(dir.path()));
	let data = sent_data(dir.path(), &app, &secret, json!({})).await;
	assert_eq!(auto_submitted(&data), Vec::<String>::new());
}

#[tokio::test]
async fn enabled_key_does_not_hide_an_invalid_request_auto_submitted_value() {
	let dir = tempfile::tempdir().expect("tempdir");
	let secret = add_key(dir.path(), true);
	let app = router(routed_state(dir.path()));
	let (status, body) = send(&app, &secret, json!({"auto_submitted": "sometimes"})).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	assert_eq!(body["error"]["code"], "invalid_input", "{body}");
	let spool = FsSpool::open(dir.path()).expect("spool");
	assert!(spool.list().expect("list").is_empty(), "nothing was queued");
}

#[tokio::test]
async fn configured_token_does_not_add_auto_submitted() {
	let dir = tempfile::tempdir().expect("tempdir");
	add_key(dir.path(), true);
	let app = router(routed_state(dir.path()));
	let data = sent_data(dir.path(), &app, TOKEN.as_str(), json!({})).await;
	assert_eq!(auto_submitted(&data), Vec::<String>::new());
}

#[tokio::test]
async fn jmap_submission_with_an_enabled_key_does_not_add_auto_submitted() {
	let dir = tempfile::tempdir().expect("tempdir");
	let secret = add_key(dir.path(), true);
	let app = router(routed_state(dir.path()));
	let rest = sent_data(dir.path(), &app, &secret, json!({})).await;
	assert_eq!(
		auto_submitted(&rest).len(),
		1,
		"the key is enabled for REST"
	);

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
		Some(secret.as_str()),
		Some(json!({
			"using": ["urn:ietf:params:jmap:submission"],
			"methodCalls": [["EmailSubmission/set", {"accountId": "alice", "create": {"s1": {
				"emailId": email.to_string(),
				"envelope": {"mailFrom": {"email": "alice@example.org"},
					"rcptTo": [{"email": "bob@elsewhere.example"}]},
			}}}, "c1"]],
		})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let created = &body["methodResponses"][0][1]["created"]["s1"];
	let data = queued(dir.path(), created["id"].as_str().expect("submission id"));
	assert_eq!(auto_submitted(&data), Vec::<String>::new());
}

#[tokio::test]
async fn enabled_key_message_signs_auto_submitted() {
	let dir = tempfile::tempdir().expect("tempdir");
	let secret = add_key(dir.path(), true);
	let app = router(routed_state(dir.path()));
	let data = sent_data(dir.path(), &app, &secret, json!({})).await;
	assert_eq!(auto_submitted(&data).len(), 1);
	let signatures = signature_headers(&data);
	assert_eq!(signatures.len(), 1, "one signature: {signatures:?}");
	let unfolded = signatures[0].replace("\r\n\t", "").replace("\r\n ", "");
	let signed = unfolded
		.split(';')
		.map(str::trim)
		.find_map(|tag| tag.strip_prefix("h="))
		.expect("h tag");
	assert!(
		signed.split(':').any(|name| name == "auto-submitted"),
		"auto-submitted is not in the signed headers: {signed}"
	);
}
