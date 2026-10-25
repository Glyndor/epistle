//! Edges of the reach of a confined key: records by sender domain, the
//! answer for an account that is not the caller's, a binding its domains do
//! not reach, and two keys behind one secret.

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::confinement_tests::{TENANT_A, world};
use super::tests::{request, request_with_body};
use super::*;
use crate::storage::{DEFAULT_DELIVERY_LOG_DAYS, DeliveryLog, DeliveryOutcome, DeliveryRecord};

fn record(account: &str, from: &str, recipient: &str) -> DeliveryRecord {
	DeliveryRecord {
		time: 1_700_000_000,
		spool_id: uuid::Uuid::now_v7(),
		account: Some(account.to_string()),
		from: from.to_string(),
		recipient: recipient.to_string(),
		outcome: DeliveryOutcome::Delivered,
		remote: Some("mx.remote.example".into()),
		reply: Some("250 OK".into()),
		attempt: 1,
		extra: Default::default(),
		class: Default::default(),
	}
}

/// A record carries an account name and a sender. A key confined to some
/// domains lists only the records whose sender is inside them.
#[tokio::test]
async fn records_follow_the_sender_domain() {
	let dir = tempfile::tempdir().expect("tempdir");
	let log = DeliveryLog::open(dir.path(), DEFAULT_DELIVERY_LOG_DAYS);
	log.append(&record("carol", "carol@b.example", "one@elsewhere.example"))
		.expect("append");
	let app = router(world(dir.path()).with_delivery_log_days(DEFAULT_DELIVERY_LOG_DAYS));
	let create = json!({
		"name": "carol",
		"addresses": ["carol@a.example"],
		"password": "correct horse battery staple",
	});
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some(TENANT_A),
		Some(create),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	log.append(&record("carol", "carol@a.example", "two@elsewhere.example"))
		.expect("append");
	let (status, body) = request(&app, "GET", "/api/v1/deliveries", Some(TENANT_A)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let entries = body["entries"].as_array().expect("entries");
	assert_eq!(entries.len(), 1, "{body}");
	assert_eq!(entries[0]["recipient"], "two@elsewhere.example", "{body}");
}

/// An account of another tenant and an account that does not exist answer
/// the same on every route that takes a name, whatever else the request
/// carries.
#[tokio::test]
async fn a_foreign_account_and_a_missing_one_answer_alike() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(world(dir.path()));
	let calls: [(&str, &str, Option<Value>); 7] = [
		("DELETE", "", None),
		("DELETE", "?queue=discard", None),
		("PUT", "/password", Some(json!({"password": "short"}))),
		(
			"PUT",
			"/password",
			Some(json!({"password": "correct horse battery staple"})),
		),
		("PUT", "/display_name", Some(json!({"display_name": "x"}))),
		("POST", "/totp", None),
		("DELETE", "/totp", None),
	];
	for (method, suffix, body) in calls {
		let mut answers = Vec::new();
		for name in ["bob", "ghost"] {
			let path = format!("/api/v1/accounts/{name}{suffix}");
			answers
				.push(request_with_body(&app, method, &path, Some(TENANT_A), body.clone()).await);
		}
		assert_eq!(answers[0].0, StatusCode::NOT_FOUND, "{method} {suffix}");
		assert_eq!(answers[0], answers[1], "{method} {suffix}");
	}
}

/// A key bound to an account its domains do not reach owns no
/// subscriptions and no caller slots, and one whose domains reach it does.
#[test]
fn a_binding_outside_the_domains_owns_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = world(dir.path());
	let bound = |account: &str| {
		let key = crate::api::api_keys::ApiKey {
			label: format!("bound-{account}"),
			hash: crate::api::api_keys::sha256_hash("unused"),
			expires_at: None,
			ip_cidr: None,
			scopes: vec!["read".to_string()],
			domains: vec!["a.example".to_string()],
			account: Some(account.to_string()),
		};
		Principal::of_key(&key, None)
	};
	let owner = |account: &str| super::jmap::push_subscription::owner_of(&state, &bound(account));
	assert_eq!(owner("ann"), Some("account:ann".to_string()));
	assert_eq!(owner("bob"), None);
	assert_eq!(owner("nobody"), None);
}

/// Two keys behind one secret cannot lend each other their scope: the
/// request is not served with the reach of either.
#[tokio::test]
async fn two_keys_behind_one_secret_do_not_widen_each_other() {
	let dir = tempfile::tempdir().expect("tempdir");
	let hash = crate::api::api_keys::sha256_hash("shared-secret");
	std::fs::write(
		dir.path().join("api_keys.toml"),
		format!(
			"[[keys]]\nlabel = \"first\"\nhash = \"{hash}\"\nscopes = [\"read\"]\n\n\
			 [[keys]]\nlabel = \"second\"\nhash = \"{hash}\"\nscopes = [\"write\"]\n\
			 domains = [\"a.example\"]\n"
		),
	)
	.expect("write keys");
	let state = world(dir.path());
	let app = router(state.clone());
	let create = json!({
		"name": "mallory",
		"addresses": ["mallory@b.example"],
		"password": "correct horse battery staple",
	});
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some("shared-secret"),
		Some(create),
	)
	.await;
	assert_ne!(status, StatusCode::OK, "{body}");
	assert!(
		state
			.accounts()
			.iter()
			.all(|account| account.name != "mallory"),
		"the account must not exist"
	);
}
