//! The reach of a key is composed. A key may declare an account and domains
//! at the same time, and both narrow it: the account binding says which
//! account the key acts for, the domain binding says which accounts live
//! inside its tenant. A key confined to a domain also reaches the records of
//! the accounts inside that domain, and no others.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::json;

use super::tests::{TOKEN, request, request_with_body};
use super::*;
use crate::directory_store::AccountStore;
use crate::storage::{
	DEFAULT_DELIVERY_LOG_DAYS, DeliveryLog, DeliveryOutcome, DeliveryRecord, FsSpool,
};

/// A key confined to `a.example`.
pub(super) const TENANT_A: &str = "tenant-a-secret";
/// A key bound to `ann`, which lives inside `a.example`.
const BOUND_INSIDE: &str = "bound-inside-secret";
/// A key bound to `bob`, which lives in `b.example`.
const BOUND_OUTSIDE: &str = "bound-outside-secret";
/// A key bound to `ann` and to no domain.
const BOUND_ONLY: &str = "bound-only-secret";

fn key(
	label: &str,
	secret: &str,
	domains: &[&str],
	account: Option<&str>,
) -> crate::api::api_keys::ApiKey {
	crate::api::api_keys::ApiKey {
		label: label.to_string(),
		hash: crate::api::api_keys::sha256_hash(secret),
		expires_at: None,
		ip_cidr: None,
		scopes: vec![
			"read".to_string(),
			"write".to_string(),
			"send".to_string(),
			"scim".to_string(),
		],
		domains: domains.iter().map(|d| (*d).to_string()).collect(),
		account: account.map(str::to_string),
	}
}

/// Two tenants, `ann` in `a.example` and `bob` in `b.example`, and the three
/// keys the tests below use.
pub(super) fn world(dir: &std::path::Path) -> ApiState {
	let mut keys = crate::api::ApiKeyStore::open(dir).expect("key store");
	keys.add(key("tenant-a", TENANT_A, &["a.example"], None))
		.expect("add key");
	keys.add(key(
		"bound-inside",
		BOUND_INSIDE,
		&["a.example"],
		Some("ann"),
	))
	.expect("add key");
	keys.add(key(
		"bound-outside",
		BOUND_OUTSIDE,
		&["a.example"],
		Some("bob"),
	))
	.expect("add key");
	keys.add(key("bound-only", BOUND_ONLY, &[], Some("ann")))
		.expect("add key");
	drop(keys);
	let account = |name: &str, address: &str| crate::config::Account {
		display_name: None,
		name: name.to_string(),
		addresses: vec![address.to_string()],
		password_hash: Some("$argon2id$secret".to_string()),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	};
	let domains = vec!["a.example".to_string(), "b.example".to_string()];
	// The per-account directories the state counters read.
	for account in ["ann", "bob"] {
		std::fs::create_dir_all(dir.join("accounts").join(account)).expect("mkdir");
	}
	let store = Arc::new(
		AccountStore::open(
			dir,
			domains.clone(),
			std::collections::HashMap::new(),
			vec![
				account("ann", "ann@a.example"),
				account("bob", "bob@b.example"),
			],
		)
		.expect("open store"),
	);
	ApiState::new(
		&crate::smtp::auth::tests::base::hash(TOKEN.as_str()),
		dir.to_path_buf(),
		domains,
		store.clone(),
		FsSpool::open(dir).expect("open spool"),
	)
	.with_directory(store.handle())
}

/// One record of the delivery log, tagged with the account that produced it.
fn record(account: Option<&str>, recipient: &str) -> DeliveryRecord {
	DeliveryRecord {
		time: 1_700_000_000,
		spool_id: uuid::Uuid::now_v7(),
		account: account.map(str::to_string),
		from: account
			.map(|name| format!("{name}@a.example"))
			.unwrap_or_else(|| "external@example.org".to_string()),
		recipient: recipient.to_string(),
		outcome: DeliveryOutcome::Delivered,
		remote: Some("mx.remote.example".into()),
		reply: Some("250 OK".into()),
		attempt: 1,
		extra: BTreeMap::new(),
		class: Default::default(),
	}
}

fn write_records(dir: &std::path::Path, records: &[DeliveryRecord]) {
	let log = DeliveryLog::open(dir, DEFAULT_DELIVERY_LOG_DAYS);
	for record in records {
		log.append(record).expect("append");
	}
}

/// A key bound to an account that lives outside the domains it declares
/// reaches no account at all: the account binding and the domain binding
/// narrow the same key, and both apply.
#[tokio::test]
async fn a_key_bound_to_an_account_outside_its_domains_reaches_no_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(world(dir.path()));
	let (status, body) = request(&app, "GET", "/jmap/session", Some(BOUND_OUTSIDE)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(
		body["accounts"].as_object().expect("accounts").len(),
		0,
		"the account lives in another tenant: {body}"
	);
}

/// A key bound to one account reaches that account and no other, even when
/// it declares no domain at all.
#[tokio::test]
async fn a_key_bound_to_an_account_reaches_only_that_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(world(dir.path()));
	let (status, body) = request(&app, "GET", "/jmap/session", Some(BOUND_ONLY)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let accounts = body["accounts"].as_object().expect("accounts");
	assert_eq!(accounts.len(), 1, "{body}");
	assert!(accounts.contains_key("ann"), "{body}");
}

/// The same key, bound to an account that does live inside its domains,
/// reaches that account.
#[tokio::test]
async fn a_key_bound_to_an_account_inside_its_domains_reaches_that_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(world(dir.path()));
	let (status, body) = request(&app, "GET", "/jmap/session", Some(BOUND_INSIDE)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let accounts = body["accounts"].as_object().expect("accounts");
	assert_eq!(accounts.len(), 1, "{body}");
	assert!(accounts.contains_key("ann"), "{body}");
}

/// The composed key cannot read the account it is bound to, because that
/// account is outside the domains it declares.
#[tokio::test]
async fn a_key_bound_outside_its_domains_cannot_read_the_foreign_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(world(dir.path()));
	let call = json!({
		"methodCalls": [["Mailbox/get", { "accountId": "bob" }, "m1"]],
	});
	let (status, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(BOUND_OUTSIDE), Some(call)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(
		body["methodResponses"][0][1]["type"], "accountNotFound",
		"{body}"
	);
}

/// Nor can it send as that account.
#[tokio::test]
async fn a_key_bound_outside_its_domains_cannot_send_from_the_foreign_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(world(dir.path()));
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/api/v1/send",
		Some(BOUND_OUTSIDE),
		Some(json!({
			"from": "bob@b.example",
			"to": ["someone@elsewhere.example"],
			"subject": "s",
			"text": "t",
		})),
	)
	.await;
	assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
	assert_eq!(body["error"]["code"], "forbidden_from", "{body}");
}

/// Nor does it read that account's delivery records.
#[tokio::test]
async fn a_key_bound_outside_its_domains_cannot_read_the_foreign_records() {
	let dir = tempfile::tempdir().expect("tempdir");
	write_records(
		dir.path(),
		&[
			record(Some("ann"), "one@elsewhere.example"),
			record(Some("bob"), "two@elsewhere.example"),
		],
	);
	let app = router(world(dir.path()).with_delivery_log_days(DEFAULT_DELIVERY_LOG_DAYS));
	let (status, body) = request(&app, "GET", "/api/v1/deliveries", Some(BOUND_OUTSIDE)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(
		body["entries"].as_array().expect("entries").len(),
		0,
		"the bound account is out of the declared domains: {body}"
	);
}

/// A key confined to a domain reads the records of the accounts inside it,
/// and only those.
#[tokio::test]
async fn a_domain_confined_key_reads_the_records_of_its_own_accounts() {
	let dir = tempfile::tempdir().expect("tempdir");
	write_records(
		dir.path(),
		&[
			record(Some("ann"), "one@elsewhere.example"),
			record(Some("bob"), "two@elsewhere.example"),
			record(None, "three@elsewhere.example"),
		],
	);
	let app = router(world(dir.path()).with_delivery_log_days(DEFAULT_DELIVERY_LOG_DAYS));
	let (status, body) = request(&app, "GET", "/api/v1/deliveries", Some(TENANT_A)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let entries = body["entries"].as_array().expect("entries");
	assert_eq!(entries.len(), 1, "{body}");
	assert_eq!(entries[0]["account"], "ann", "{body}");
}

/// The administrator still sees every record, attributed or not.
#[tokio::test]
async fn the_configured_token_still_reads_every_record() {
	let dir = tempfile::tempdir().expect("tempdir");
	write_records(
		dir.path(),
		&[
			record(Some("ann"), "one@elsewhere.example"),
			record(Some("bob"), "two@elsewhere.example"),
			record(None, "three@elsewhere.example"),
		],
	);
	let app = router(world(dir.path()).with_delivery_log_days(DEFAULT_DELIVERY_LOG_DAYS));
	let (status, body) = request(&app, "GET", "/api/v1/deliveries", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(
		body["entries"].as_array().expect("entries").len(),
		3,
		"{body}"
	);
}

/// Creating an account in another tenant's domain is refused the same way on
/// both provisioning surfaces: the REST one and the SCIM one.
#[tokio::test]
async fn both_provisioning_surfaces_refuse_a_foreign_address_the_same_way() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = world(dir.path());
	let app = router(state.clone());
	let rest = json!({
		"name": "mallory",
		"addresses": ["mallory@b.example"],
		"password": "correct horse battery staple",
	});
	let (rest_status, rest_body) =
		request_with_body(&app, "POST", "/api/v1/accounts", Some(TENANT_A), Some(rest)).await;
	let scim = json!({
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "mallory",
		"active": true,
		"emails": [{"value": "mallory@b.example"}],
	});
	let (scim_status, scim_body) =
		request_with_body(&app, "POST", "/scim/v2/Users", Some(TENANT_A), Some(scim)).await;
	assert_eq!(
		rest_status,
		StatusCode::BAD_REQUEST,
		"the REST surface: {rest_body}"
	);
	assert_eq!(scim_status, rest_status, "the SCIM surface: {scim_body}");
	assert!(
		state
			.accounts()
			.iter()
			.all(|account| account.name != "mallory"),
		"neither surface may create the account"
	);
}
