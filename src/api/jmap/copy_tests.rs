use crate::api::{ApiState, router};
use crate::imap::mailbox;
use crate::storage::MessageCrypto;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

fn state(dir: &std::path::Path, token: &str) -> ApiState {
	let mut keys = crate::api::ApiKeyStore::open(dir).expect("keys");
	keys.add(crate::api::api_keys::ApiKey {
		label: "tenant".into(),
		hash: crate::api::api_keys::sha256_hash(token),
		expires_at: None,
		ip_cidr: None,
		scopes: vec!["read".into(), "write".into()],
		domains: vec!["example.org".into()],
	})
	.expect("key");
	drop(keys);
	let accounts = [
		("source", "example.org"),
		("dest", "example.org"),
		("private", "other.org"),
	]
	.into_iter()
	.map(|(name, domain)| crate::config::Account {
		name: name.into(),
		addresses: vec![format!("{name}@{domain}")],
		password_hash: None,
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	})
	.collect();
	let domains = vec!["example.org".into(), "other.org".into()];
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			dir,
			domains.clone(),
			std::collections::HashMap::new(),
			accounts,
		)
		.expect("store"),
	);
	ApiState::new(
		&crate::smtp::auth::tests::hash(&format!("{token}-admin")),
		dir.into(),
		domains,
		store,
		crate::storage::FsSpool::open(dir).expect("spool"),
	)
}

async fn copy(app: axum::Router, token: &str, args: Value) -> Vec<u8> {
	let response = app
		.oneshot(
			Request::builder()
				.method("POST")
				.uri("/jmap/api")
				.header("Authorization", format!("Bearer {token}"))
				.header("Content-Type", "application/json")
				.body(Body::from(
					json!({"methodCalls": [["Email/copy", args, "c"]]}).to_string(),
				))
				.expect("request"),
		)
		.await
		.expect("response");
	assert_eq!(response.status(), StatusCode::OK);
	to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body")
		.to_vec()
}

#[tokio::test]
async fn email_copy_between_accessible_accounts_wire() {
	let dir = tempfile::tempdir().expect("tempdir");
	let token = crate::smtp::auth::tests::fixture_password();
	let state = state(dir.path(), token);
	let raw = b"Subject: source\r\n\r\nhello";
	let id =
		mailbox::append(dir.path(), "source", "INBOX", &[], raw, state.crypto()).expect("append");
	let bytes = copy(
		router(state),
		token,
		json!({"accountId": "dest", "fromAccountId": "source",
        "create": {"k": {"id": id.to_string(), "mailboxIds": {"INBOX": true}}}}),
	)
	.await;
	let value: Value = serde_json::from_slice(&bytes).expect("json");
	let new_id = value["methodResponses"][0][1]["created"]["k"]["id"]
		.as_str()
		.unwrap_or("");
	let expected = json!({"methodResponses": [["Email/copy", {"accountId": "dest",
        "fromAccountId": "source", "created": {"k": {"id": new_id, "blobId": new_id,
            "threadId": new_id, "size": raw.len()}}, "notCreated": {}}, "c"]]});
	assert!(
		uuid::Uuid::parse_str(new_id).is_ok() && bytes == expected.to_string().as_bytes(),
		"Email/copy must return an exact successful cross-account copy response using id"
	);
	let crypto = MessageCrypto::disabled();
	let source = mailbox::Snapshot::open(dir.path(), "source", "INBOX", &crypto).expect("source");
	let dest = mailbox::Snapshot::open(dir.path(), "dest", "INBOX", &crypto).expect("dest");
	assert_eq!(
		source.messages().count(),
		1,
		"copy must preserve the source message"
	);
	assert_eq!(
		dest.messages().count(),
		1,
		"copy must create one destination message"
	);
	assert!(
		super::super::objects::find_email_raw(dir.path(), "dest", new_id, &crypto).as_deref()
			== Some(raw.as_slice()),
		"copy must preserve the exact source message bytes"
	);
}

#[tokio::test]
async fn email_copy_denies_inaccessible_source_wire() {
	let dir = tempfile::tempdir().expect("tempdir");
	let token = crate::smtp::auth::tests::fixture_password();
	let state = state(dir.path(), token);
	let id = mailbox::append(
		dir.path(),
		"private",
		"INBOX",
		&[],
		b"Subject: private\r\n\r\nbody",
		state.crypto(),
	)
	.expect("append");
	let bytes = copy(
		router(state),
		token,
		json!({"accountId": "dest", "fromAccountId": "private",
        "create": {"k": {"id": id.to_string(), "mailboxIds": {"INBOX": true}}}}),
	)
	.await;
	let expected = json!({"methodResponses": [["error", {"type": "fromAccountNotFound"}, "c"]]});
	assert!(
		bytes == expected.to_string().as_bytes(),
		"Email/copy must return fromAccountNotFound for an inaccessible source"
	);
	let dest = mailbox::Snapshot::open(dir.path(), "dest", "INBOX", &MessageCrypto::disabled())
		.expect("dest");
	assert_eq!(
		dest.messages().count(),
		0,
		"denied copy must leave destination empty"
	);
}
