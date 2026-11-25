//! What a dry run says to a key that must not learn it: the shared
//! suppression list, the mailboxes behind an alias that mixes tenants, and
//! the budget of the request as the real send charges it.

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::base::{TOKEN, request_with_body, test_state};
use super::router;
use super::send_class::state as class_state;
use crate::smtp::ratelimit::SendLimiter;

const ALICE: &str = "alice-bound-secret";
const CONFINED: &str = "confined-send-secret";
const SEND_ONLY: &str = "unconfined-send-secret";
const MANAGER: &str = "unconfined-manager-secret";

fn key(
	label: &str,
	secret: &str,
	scopes: &[&str],
	domains: &[&str],
	account: Option<&str>,
) -> crate::api::api_keys::ApiKey {
	crate::api::api_keys::ApiKey {
		label: label.to_string(),
		hash: crate::api::api_keys::sha256_hash(secret),
		expires_at: None,
		ip_cidr: None,
		scopes: scopes.iter().map(|scope| (*scope).to_string()).collect(),
		grants: Vec::new(),
		domains: domains.iter().map(|domain| (*domain).to_string()).collect(),
		account: account.map(str::to_string),
		auto_submitted: false,
	}
}

fn add_keys(dir: &std::path::Path) {
	let mut keys = crate::api::ApiKeyStore::open(dir).expect("keys");
	for one in [
		key("alice", ALICE, &["send"], &[], Some("alice")),
		key(
			"confined",
			CONFINED,
			&["send", "manage:read"],
			&["example.org"],
			None,
		),
		key("send-only", SEND_ONLY, &["send"], &[], None),
		key("manager", MANAGER, &["send", "manage:read"], &[], None),
	] {
		keys.add(one).expect("add key");
	}
}

async fn call(app: &axum::Router, bearer: &str, body: Value) -> (StatusCode, Value) {
	request_with_body(app, "POST", "/api/v1/send", Some(bearer), Some(body)).await
}

fn marketing(to: &[&str]) -> Value {
	json!({
		"from": "alice@example.org", "to": to, "subject": "s", "text": "hi",
		"class": "marketing", "dry_run": true,
		"list_unsubscribe": ["https://example.org/u"], "list_unsubscribe_post": true,
	})
}

#[tokio::test]
async fn a_marketing_dry_run_does_not_tell_what_the_shared_list_holds_to_a_key_that_may_not_read_it()
 {
	let mut answers: Vec<(String, StatusCode, Value)> = Vec::new();
	for suppressed in [true, false] {
		let dir = tempfile::tempdir().expect("tempdir");
		add_keys(dir.path());
		if suppressed {
			crate::queue::SuppressionList::open(dir.path())
				.expect("list")
				.suppress("gone@elsewhere.example");
		}
		let app = router(test_state(dir.path(), 0));
		for secret in [ALICE, CONFINED, SEND_ONLY] {
			let (status, body) = call(
				&app,
				secret,
				marketing(&["kept@elsewhere.example", "gone@elsewhere.example"]),
			)
			.await;
			answers.push((format!("{secret} {suppressed}"), status, body));
			// Every recipient on the list is the other way to ask.
			let (status, body) = call(&app, secret, marketing(&["gone@elsewhere.example"])).await;
			answers.push((format!("{secret} {suppressed} alone"), status, body));
		}
	}
	for (who, status, body) in &answers {
		assert_eq!(*status, StatusCode::FORBIDDEN, "{who}: {body}");
		assert_eq!(body["error"]["code"], "forbidden", "{who}");
		assert!(body.get("suppressed").is_none(), "{who}: {body}");
		assert!(!body.to_string().contains("gone@"), "{who}: {body}");
	}
	// What a key gets does not depend on what the list holds.
	for secret in [ALICE, CONFINED, SEND_ONLY] {
		let same: Vec<_> = answers
			.iter()
			.filter(|(who, ..)| who.starts_with(secret) && !who.ends_with("alone"))
			.map(|(_, status, body)| (status, body))
			.collect();
		assert_eq!(same.len(), 2);
		assert_eq!(same[0], same[1], "{secret}");
	}
}

#[tokio::test]
async fn a_marketing_dry_run_still_works_for_an_unconfined_key_that_reads_the_management_views() {
	let dir = tempfile::tempdir().expect("tempdir");
	add_keys(dir.path());
	crate::queue::SuppressionList::open(dir.path())
		.expect("list")
		.suppress("gone@elsewhere.example");
	let app = router(test_state(dir.path(), 0));
	for secret in [MANAGER, TOKEN.as_str()] {
		let (status, body) = call(
			&app,
			secret,
			marketing(&["kept@elsewhere.example", "gone@elsewhere.example"]),
		)
		.await;
		assert_eq!(status, StatusCode::OK, "{body}");
		assert_eq!(body["suppressed"], json!(["gone@elsewhere.example"]));
	}
}

#[tokio::test]
async fn a_class_the_credential_or_the_account_holds_is_the_one_asked_about() {
	let dir = tempfile::tempdir().expect("tempdir");
	add_keys(dir.path());
	crate::queue::SuppressionList::open(dir.path())
		.expect("list")
		.suppress("gone@elsewhere.example");
	// The key is bound to marketing, and the request names no class.
	let binding = crate::evidence::bindings::api_key_key_of_token(ALICE);
	crate::evidence::bindings::update(dir.path(), |bindings| {
		bindings
			.credentials
			.insert(binding, crate::evidence::MailClass::Marketing);
	})
	.expect("bind");
	let (state, _) = class_state(dir.path());
	let app = router(state);
	let mut body = marketing(&["gone@elsewhere.example"]);
	body.as_object_mut().expect("object").remove("class");
	let (status, answer) = call(&app, ALICE, body).await;
	assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
	// Asking for less than the floor of the credential does not lower it.
	let (status, answer) = call(
		&app,
		ALICE,
		json!({"from": "alice@example.org", "to": ["x@elsewhere.example"], "subject": "s",
			"text": "hi", "class": "personal", "dry_run": true}),
	)
	.await;
	assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
}

#[tokio::test]
async fn a_personal_dry_run_is_open_to_every_key_that_may_send() {
	let dir = tempfile::tempdir().expect("tempdir");
	add_keys(dir.path());
	let app = router(test_state(dir.path(), 0));
	for secret in [ALICE, CONFINED, SEND_ONLY, MANAGER] {
		let (status, body) = call(
			&app,
			secret,
			json!({"from": "alice@example.org", "to": ["x@elsewhere.example"], "subject": "s",
				"text": "hi", "dry_run": true}),
		)
		.await;
		assert_eq!(status, StatusCode::OK, "{secret}: {body}");
	}
}

/// carol of example.org takes messages of 64 KiB at most; bob is of another
/// tenant; the alias holds both. Whether bob receives is `receive_off`.
fn alias_world(dir: &std::path::Path, bob_receives: bool) -> crate::api::ApiState {
	use crate::smtp::directory::{AliasSpec, Directory};
	let account = |name: &str, domain: &str, quota: Option<u64>| crate::config::Account {
		send: None,
		receive: None,
		name: name.to_string(),
		addresses: vec![format!("{name}@{domain}")],
		password_hash: Some("$argon2id$secret".to_string()),
		catch_all: Vec::new(),
		quota_bytes: quota,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
		display_name: None,
	};
	let store = Arc::new(
		crate::directory_store::AccountStore::open(
			dir,
			vec!["example.org".to_string(), "example.net".to_string()],
			std::collections::HashMap::new(),
			vec![
				account("alice", "example.org", None),
				account("carol", "example.org", None),
				account("bob", "example.net", None),
			],
		)
		.expect("store"),
	);
	let directory = Directory::new(
		["example.org".to_string(), "example.net".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("carol@example.org".to_string(), "carol".to_string()),
			("bob@example.net".to_string(), "bob".to_string()),
		],
	)
	.with_aliases([(
		"team@example.org".to_string(),
		AliasSpec {
			members: vec![
				"carol@example.org".to_string(),
				"bob@example.net".to_string(),
			],
			senders: Vec::new(),
			hidden: true,
			list_id: None,
		},
	)])
	.with_limits(crate::limits::test_support::shared(
		"[[limit_scope]]\naccount = \"carol\"\nmax_message_size = 65536\n",
	))
	.with_switches(
		Vec::new(),
		if bob_receives {
			Vec::new()
		} else {
			vec!["bob".to_string()]
		},
	);
	crate::api::ApiState::new(
		&crate::smtp::auth::tests::base::hash(TOKEN.as_str()),
		dir.to_path_buf(),
		vec!["example.org".to_string(), "example.net".to_string()],
		store,
		crate::storage::FsSpool::open(dir).expect("spool"),
	)
	.with_directory(crate::directory_store::DirectoryHandle::new(directory))
}

#[tokio::test]
async fn an_alias_of_two_tenants_is_not_measured_for_a_confined_key_whoever_receives() {
	let mut seen = Vec::new();
	for bob_receives in [true, false] {
		let dir = tempfile::tempdir().expect("tempdir");
		add_keys(dir.path());
		let app = router(alias_world(dir.path(), bob_receives));
		let personal = json!({"from": "alice@example.org", "to": ["team@example.org"],
			"subject": "s", "text": "x".repeat(70_000), "dry_run": true});
		let (status, body) = call(&app, CONFINED, personal.clone()).await;
		seen.push((status, body));
		// The key that reaches every account is told, as the real send is,
		// whoever else receives.
		let (status, body) = call(&app, TOKEN.as_str(), personal).await;
		assert_eq!(
			status,
			StatusCode::PAYLOAD_TOO_LARGE,
			"{bob_receives}: {body}"
		);
	}
	assert_eq!(
		seen[0], seen[1],
		"bob's switch changed what the key was told"
	);
	assert_eq!(seen[0].0, StatusCode::OK, "{:?}", seen[0]);
}

#[tokio::test]
async fn a_dry_run_asks_for_as_many_units_as_the_real_send_charges() {
	let dir = tempfile::tempdir().expect("tempdir");
	let limiter = Arc::new(SendLimiter::for_authenticated_keys(60));
	let app = router(test_state(dir.path(), 0).with_submission_limit(Some(limiter), Some(1)));
	let two = |dry: bool| {
		json!({"from": "alice@example.org",
		"to": ["a@elsewhere.example", "b@elsewhere.example"],
		"subject": "s", "text": "hi", "dry_run": dry})
	};
	let (status, body) = call(&app, TOKEN.as_str(), two(true)).await;
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
	let (status, body) = call(&app, TOKEN.as_str(), two(false)).await;
	assert_eq!(
		status,
		StatusCode::TOO_MANY_REQUESTS,
		"the real send says the same: {body}"
	);
	// What was asked took nothing: one recipient still fits.
	let (status, body) = call(
		&app,
		TOKEN.as_str(),
		json!({"from": "alice@example.org", "to": ["a@elsewhere.example"],
			"subject": "s", "text": "hi", "dry_run": true}),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_dry_run_counts_the_recipients_left_after_the_suppressed_ones() {
	let dir = tempfile::tempdir().expect("tempdir");
	add_keys(dir.path());
	crate::queue::SuppressionList::open(dir.path())
		.expect("list")
		.suppress("gone@elsewhere.example");
	let limiter = Arc::new(SendLimiter::for_authenticated_keys(60));
	let app = router(test_state(dir.path(), 0).with_submission_limit(Some(limiter), Some(1)));
	let (status, body) = call(
		&app,
		MANAGER,
		marketing(&["kept@elsewhere.example", "gone@elsewhere.example"]),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "one unit is left to charge: {body}");
	assert_eq!(body["recipients"], 1);
}
