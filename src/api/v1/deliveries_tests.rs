//! `GET /api/v1/deliveries` against temporary data directories.

use std::collections::BTreeMap;

use crate::api::router;
use crate::api::state::ApiState;
use crate::api::tests::{TOKEN, request, test_state};
use crate::storage::{DEFAULT_DELIVERY_LOG_DAYS, DeliveryLog, DeliveryOutcome, DeliveryRecord};

fn record(
	time: u64,
	account: Option<&str>,
	recipient: &str,
	outcome: DeliveryOutcome,
) -> DeliveryRecord {
	DeliveryRecord {
		time,
		spool_id: uuid::Uuid::now_v7(),
		account: account.map(str::to_string),
		from: account.unwrap_or("external@example.org").into(),
		recipient: recipient.into(),
		outcome,
		remote: Some("mx.remote.example".into()),
		reply: Some("250 OK".into()),
		attempt: 1,
		extra: BTreeMap::new(),
	}
}

fn write_records(dir: &std::path::Path, records: &[DeliveryRecord]) {
	let log = DeliveryLog::open(dir, DEFAULT_DELIVERY_LOG_DAYS);
	for record in records {
		log.append(record).expect("append");
	}
}

/// An `ApiState` that knows the delivery-log retention; otherwise the
/// 404 path on a disabled log would mask every test. Use this when no
/// API key is involved.
fn state_with_log(dir: &std::path::Path) -> ApiState {
	test_state(dir, 0).with_delivery_log_days(DEFAULT_DELIVERY_LOG_DAYS)
}

#[tokio::test]
async fn admin_sees_every_record() {
	let dir = tempfile::tempdir().expect("tempdir");
	write_records(
		dir.path(),
		&[
			record(
				1_700_000_000,
				Some("alice@example.org"),
				"bob@elsewhere.example",
				DeliveryOutcome::Delivered,
			),
			record(
				1_700_000_010,
				Some("carol@example.org"),
				"dan@elsewhere.example",
				DeliveryOutcome::Failed,
			),
		],
	);
	let app = router(state_with_log(dir.path()));
	let (status, body) = request(&app, "GET", "/api/v1/deliveries", Some(TOKEN.as_str())).await;
	assert_eq!(status, axum::http::StatusCode::OK);
	let entries = body["entries"].as_array().expect("entries");
	assert_eq!(entries.len(), 2);
}

#[tokio::test]
async fn an_account_bound_key_only_sees_its_own_records() {
	let dir = tempfile::tempdir().expect("tempdir");
	write_records(
		dir.path(),
		&[
			// The test state below creates one account `alice`; the
			// key is bound to that name (a key's `account` is a name,
			// not an address), so the records that the key may see are
			// the ones tagged with `account = "alice"`.
			record(
				1_700_000_000,
				Some("alice"),
				"bob@elsewhere.example",
				DeliveryOutcome::Delivered,
			),
			record(
				1_700_000_010,
				Some("carol"),
				"dan@elsewhere.example",
				DeliveryOutcome::Failed,
			),
		],
	);
	// Install the account-bound key on alice first; the test state
	// below reads `api_keys.toml` from the same directory, so the order
	// is `key`, then `state`. The key has the full Read/Write/Send/Scim
	// scope so it passes the bearer middleware, and `/api/v1/deliveries`
	// is on `path_is_account_scoped` so the `confine` gate lets it
	// through too.
	let mut key_store = crate::api::ApiKeyStore::open(dir.path()).expect("open key store");
	key_store
		.add(crate::api::api_keys::ApiKey {
			label: "alice-only".into(),
			hash: crate::api::api_keys::sha256_hash("alice-secret"),
			expires_at: None,
			ip_cidr: None,
			scopes: ["read", "write", "send", "scim"]
				.iter()
				.map(|scope| scope.to_string())
				.collect(),
			domains: Vec::new(),
			account: Some("alice".into()),
		})
		.expect("add key");
	let app = router(state_with_log(dir.path()));
	// Even when the caller passes `account=carol`, an account-bound
	// key is restricted to its own account: the handler ignores the
	// caller's filter and pins `account = <principal>`.
	let (status, body) = request(
		&app,
		"GET",
		"/api/v1/deliveries?account=carol",
		Some("alice-secret"),
	)
	.await;
	assert_eq!(status, axum::http::StatusCode::OK);
	let entries = body["entries"].as_array().expect("entries");
	assert_eq!(
		entries.len(),
		1,
		"an account key can only see its own account's records"
	);
	assert_eq!(entries[0]["account"], "alice");

	// Without the `account` filter, the alice key only sees her own
	// records.
	let (status, body) = request(&app, "GET", "/api/v1/deliveries", Some("alice-secret")).await;
	assert_eq!(status, axum::http::StatusCode::OK);
	let entries = body["entries"].as_array().expect("entries");
	assert_eq!(entries.len(), 1);
	assert_eq!(entries[0]["account"], "alice");
}

#[tokio::test]
async fn a_disabled_log_returns_not_found() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = super::tests::test_state(dir.path(), 0);
	let app = router(state);
	let (status, _body) = request(&app, "GET", "/api/v1/deliveries", Some(TOKEN.as_str())).await;
	assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn filters_by_recipient_and_outcome() {
	let dir = tempfile::tempdir().expect("tempdir");
	write_records(
		dir.path(),
		&[
			record(
				1_700_000_000,
				Some("alice@example.org"),
				"bob@elsewhere.example",
				DeliveryOutcome::Delivered,
			),
			record(
				1_700_000_010,
				Some("alice@example.org"),
				"carol@elsewhere.example",
				DeliveryOutcome::Failed,
			),
		],
	);
	let app = router(state_with_log(dir.path()));
	let (status, body) = request(
		&app,
		"GET",
		"/api/v1/deliveries?outcome=failed",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, axum::http::StatusCode::OK);
	let entries = body["entries"].as_array().expect("entries");
	assert_eq!(entries.len(), 1);
	assert_eq!(entries[0]["recipient"], "carol@elsewhere.example");
	assert_eq!(entries[0]["outcome"], "failed");
}

#[tokio::test]
async fn an_unknown_outcome_is_a_400() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(state_with_log(dir.path()));
	let (status, body) = request(
		&app,
		"GET",
		"/api/v1/deliveries?outcome=wonky",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
	assert_eq!(body["error"]["code"], "invalid_input");
}

#[tokio::test]
async fn the_wire_shape_carries_every_record_field() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut extra = BTreeMap::new();
	extra.insert("campaign".into(), "winter".into());
	let mut record = record(
		1_700_000_000,
		Some("alice@example.org"),
		"bob@elsewhere.example",
		DeliveryOutcome::Delivered,
	);
	record.extra = extra;
	write_records(dir.path(), &[record]);
	let app = router(state_with_log(dir.path()));
	let (status, body) = request(&app, "GET", "/api/v1/deliveries", Some(TOKEN.as_str())).await;
	assert_eq!(status, axum::http::StatusCode::OK);
	let entry = &body["entries"][0];
	assert_eq!(entry["recipient"], "bob@elsewhere.example");
	assert_eq!(entry["outcome"], "delivered");
	assert_eq!(entry["account"], "alice@example.org");
	assert_eq!(entry["extra"]["campaign"], "winter");
}

#[tokio::test]
async fn limit_caps_the_page_size() {
	let dir = tempfile::tempdir().expect("tempdir");
	let records: Vec<_> = (0..5)
		.map(|i| {
			record(
				1_700_000_000 + i,
				Some("alice@example.org"),
				&format!("r{i}@elsewhere.example"),
				DeliveryOutcome::Delivered,
			)
		})
		.collect();
	write_records(dir.path(), &records);
	let app = router(state_with_log(dir.path()));
	let (status, body) = request(
		&app,
		"GET",
		"/api/v1/deliveries?limit=2",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, axum::http::StatusCode::OK);
	let entries = body["entries"].as_array().expect("entries");
	assert_eq!(entries.len(), 2);
}

#[tokio::test]
async fn the_response_never_carries_a_message_body() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut record = record(
		1_700_000_000,
		Some("alice@example.org"),
		"bob@elsewhere.example",
		DeliveryOutcome::Delivered,
	);
	record.reply = Some("250 OK".into());
	write_records(dir.path(), &[record]);
	let app = router(state_with_log(dir.path()));
	let (status, body) = request(&app, "GET", "/api/v1/deliveries", Some(TOKEN.as_str())).await;
	assert_eq!(status, axum::http::StatusCode::OK);
	let entry = &body["entries"][0];
	let serialized = serde_json::to_string(entry).unwrap();
	assert!(!serialized.contains("Subject:"));
	assert!(!serialized.contains("body"));
}
