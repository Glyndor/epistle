//! What an `envelope_from` (and a `Sender`) that differs from `From` must not
//! slip past: the domains a key is confined to, the suppression lists keyed
//! by sender, and the submission budget of every tenant whose domain the
//! message is sent under. The account owns `ops@other.example` as a member of
//! a list, so only the rules under test can refuse it.

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use serde_json::{Value, json};

use super::base::{TOKEN, request_with_body, test_state};
use super::router;
use crate::directory_store::DirectoryHandle;
use crate::smtp::directory::{AliasSpec, Directory};
use crate::storage::FsSpool;

const CONFINED: &str = "confined-secret";

/// `alice` owns `alice@example.org` and is a member of `ops@other.example`, a
/// list in another hosted domain.
fn directory() -> Directory {
	Directory::new(
		["example.org".to_string(), "other.example".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	)
	.with_aliases([(
		"ops@other.example".to_string(),
		AliasSpec {
			members: vec!["alice@example.org".to_string()],
			senders: Vec::new(),
			hidden: true,
			list_id: None,
		},
	)])
}

/// A key confined to `example.org` that is not bound to an account.
fn add_confined_key(dir: &std::path::Path) {
	let mut keys = crate::api::ApiKeyStore::open(dir).expect("open key store");
	keys.add(crate::api::api_keys::ApiKey {
		label: "confined".to_string(),
		hash: crate::api::api_keys::sha256_hash(CONFINED),
		expires_at: None,
		ip_cidr: None,
		scopes: vec!["send".to_string()],
		grants: Vec::new(),
		domains: vec!["example.org".to_string()],
		account: None,
		auto_submitted: false,
	})
	.expect("add key");
}

fn app(dir: &std::path::Path) -> Router {
	add_confined_key(dir);
	router(test_state(dir, 0).with_directory(DirectoryHandle::new(directory())))
}

async fn send(app: &Router, token: &str, extra: Value) -> (StatusCode, Value) {
	let mut body = json!({
		"from": "alice@example.org", "to": ["dest@remote.example"],
		"subject": "hello", "text": "hi",
	});
	body.as_object_mut()
		.expect("object")
		.extend(extra.as_object().expect("object").clone());
	request_with_body(app, "POST", "/api/v1/send", Some(token), Some(body)).await
}

fn queued(dir: &std::path::Path) -> usize {
	FsSpool::open(dir)
		.expect("spool")
		.list()
		.expect("list")
		.len()
}

#[tokio::test]
async fn a_key_confined_to_a_domain_cannot_send_under_an_address_of_another() {
	for field in ["envelope_from", "sender"] {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = app(dir.path());
		let extra = json!({ field: "ops@other.example" });
		// The same request from the unconfined token goes out: the account
		// does own the address, so only the key's domains refuse it.
		let (status, body) = send(&app, TOKEN.as_str(), extra.clone()).await;
		assert_eq!(status, StatusCode::OK, "{field}: {body}");
		let before = queued(dir.path());
		let (status, body) = send(&app, CONFINED, extra).await;
		assert_eq!(status, StatusCode::FORBIDDEN, "{field}: {body}");
		assert_eq!(body["error"]["code"], "forbidden_from", "{field}");
		assert_eq!(queued(dir.path()), before, "{field}: nothing was queued");
	}
}

#[tokio::test]
async fn a_confined_key_still_sends_under_its_own_domain() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = app(dir.path());
	for field in ["envelope_from", "sender"] {
		let (status, body) = send(&app, CONFINED, json!({ field: "alice@example.org" })).await;
		assert_eq!(status, StatusCode::OK, "{field}: {body}");
	}
}

/// Marketing mail from alice to `to`, with `extra` merged in.
fn marketing(to: &[&str], extra: Value) -> Value {
	let mut body = json!({
		"class": "marketing", "to": to,
		"list_unsubscribe": ["https://example.org/u"], "list_unsubscribe_post": true,
	});
	body.as_object_mut()
		.expect("object")
		.extend(extra.as_object().expect("object").clone());
	body
}

#[tokio::test]
async fn a_suppression_of_the_author_holds_whatever_the_envelope_sender() {
	for extra in [json!({}), json!({"envelope_from": "ops@other.example"})] {
		let dir = tempfile::tempdir().expect("tempdir");
		crate::queue::SuppressionList::open(dir.path())
			.expect("list")
			.suppress_for("alice@example.org", "gone@elsewhere.example");
		let app = app(dir.path());
		let (status, body) = send(
			&app,
			TOKEN.as_str(),
			marketing(
				&["kept@elsewhere.example", "gone@elsewhere.example"],
				extra.clone(),
			),
		)
		.await;
		assert_eq!(status, StatusCode::OK, "{extra}: {body}");
		assert_eq!(
			body["suppressed"],
			json!(["gone@elsewhere.example"]),
			"{extra}"
		);
		let spool = FsSpool::open(dir.path()).expect("spool");
		let entry = spool.load(spool.list().expect("list")[0]).expect("entry");
		assert_eq!(
			entry.envelope.recipients,
			["kept@elsewhere.example"],
			"{extra}"
		);
		assert_eq!(
			entry.envelope.authors.is_empty(),
			extra.get("envelope_from").is_none(),
			"{extra}: the envelope remembers the author only when it is not the sender"
		);
	}
}

#[tokio::test]
async fn a_suppression_of_the_envelope_sender_still_holds() {
	let dir = tempfile::tempdir().expect("tempdir");
	crate::queue::SuppressionList::open(dir.path())
		.expect("list")
		.suppress_for("ops@other.example", "gone@elsewhere.example");
	let app = app(dir.path());
	let (status, body) = send(
		&app,
		TOKEN.as_str(),
		marketing(
			&["kept@elsewhere.example", "gone@elsewhere.example"],
			json!({"envelope_from": "ops@other.example"}),
		),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["suppressed"], json!(["gone@elsewhere.example"]));
}

/// `example.org` is a tenant with no limit, `other.example` one that may send one recipient a minute.
fn limited(dir: &std::path::Path) -> Router {
	add_confined_key(dir);
	let tenant = |name: &str, domain: &str, per_min: Option<u32>| crate::config::Tenant {
		name: Some(name.to_string()),
		domains: vec![domain.to_string()],
		quota_bytes: None,
		max_accounts: None,
		max_domains: None,
		submission_rate_limit_per_min: per_min,
		encryption_key_file: None,
		webhook: None,
	};
	let limits = Arc::new(crate::api::TenantLimits::from_config(&[
		tenant("a", "example.org", None),
		tenant("b", "other.example", Some(1)),
	]));
	router(
		test_state(dir, 0)
			.with_directory(DirectoryHandle::new(directory()))
			.with_tenant_limits(limits),
	)
}

#[tokio::test]
async fn every_tenant_the_message_is_sent_under_is_charged() {
	for field in ["envelope_from", "sender"] {
		let dir = tempfile::tempdir().expect("tempdir");
		let app = limited(dir.path());
		let extra = json!({ field: "ops@other.example" });
		let (status, body) = send(&app, TOKEN.as_str(), extra.clone()).await;
		assert_eq!(status, StatusCode::OK, "{field}: {body}");
		let (status, body) = send(&app, TOKEN.as_str(), extra).await;
		assert_eq!(
			status,
			StatusCode::TOO_MANY_REQUESTS,
			"{field}: tenant b is spent: {body}"
		);
		assert_eq!(body["error"]["code"], "rate_limited", "{field}");
	}
}

#[tokio::test]
async fn a_send_under_the_account_own_domain_does_not_touch_the_other_tenant() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = limited(dir.path());
	for _ in 0..3 {
		let (status, body) = send(&app, TOKEN.as_str(), json!({})).await;
		assert_eq!(status, StatusCode::OK, "{body}");
	}
}
