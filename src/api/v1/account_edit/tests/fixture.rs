//! Two tenants, one account each, and the keys the quota routes are tried
//! with.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

use crate::api::ApiState;
use crate::api::api_keys::ApiKey;
use crate::directory_store::{AccountStore, DynamicAccount};

/// `manage:write`, confined to `a.test`.
pub(super) const OF_A: &str = "of-a-secret";
/// `manage:write`, no confinement.
pub(super) const WRITER: &str = "writer-secret";
/// `manage:read` only.
pub(super) const READER: &str = "reader-secret";
/// `manage:write`, bound to `alice`.
pub(super) const OF_ALICE: &str = "of-alice-secret";

pub(super) struct World {
	pub(super) _dir: tempfile::TempDir,
	pub(super) state: ApiState,
	pub(super) store: Arc<AccountStore>,
}

fn key(label: &str, secret: &str, scope: &str, domains: &[&str], account: Option<&str>) -> ApiKey {
	ApiKey {
		label: label.to_string(),
		hash: crate::api::api_keys::sha256_hash(secret),
		expires_at: None,
		ip_cidr: None,
		scopes: vec![scope.to_string()],
		grants: Vec::new(),
		domains: domains.iter().map(|domain| (*domain).to_string()).collect(),
		account: account.map(str::to_string),
		auto_submitted: false,
	}
}

fn account(name: &str, addresses: &[&str]) -> DynamicAccount {
	DynamicAccount {
		name: name.to_string(),
		addresses: addresses.iter().map(|a| (*a).to_string()).collect(),
		password_hash: crate::smtp::auth::tests::base::hash("a long enough password 1"),
		..DynamicAccount::default()
	}
}

pub(super) fn world() -> World {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().canonicalize().expect("canonical");
	let domains = vec!["a.test".to_string(), "b.test".to_string()];
	let store = Arc::new(
		AccountStore::open(
			&data_dir,
			domains.clone(),
			std::collections::HashMap::new(),
			Vec::new(),
		)
		.expect("store"),
	);
	store
		.add(account("alice", &["alice@a.test"]))
		.expect("alice");
	store.add(account("bob", &["bob@b.test"])).expect("bob");
	// An account that belongs to two tenants at once.
	store
		.add(account("split", &["split@a.test", "split@b.test"]))
		.expect("split");
	let mut keys = crate::api::ApiKeyStore::open(&data_dir).expect("key store");
	for one in [
		key("of-a", OF_A, "manage:write", &["a.test"], None),
		key("writer", WRITER, "manage:write", &[], None),
		key("reader", READER, "manage:read", &[], None),
		key("of-alice", OF_ALICE, "manage:write", &[], Some("alice")),
	] {
		keys.add(one).expect("add key");
	}
	drop(keys);
	let keyset = Arc::new(crate::api::ApiKeySet::open(&data_dir).expect("key set"));
	let state = ApiState::new(
		&crate::smtp::auth::tests::base::hash(crate::api::tests::base::TOKEN.as_str()),
		data_dir.clone(),
		domains,
		store.clone(),
		crate::storage::FsSpool::open(&data_dir).expect("spool"),
	)
	.with_directory(store.handle())
	.with_api_keys(keyset);
	World {
		_dir: dir,
		state,
		store,
	}
}

pub(super) fn token() -> &'static str {
	crate::api::tests::base::TOKEN.as_str()
}

pub(super) async fn call(
	state: &ApiState,
	method: &str,
	path: &str,
	bearer: &str,
	body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
	let mut request = Request::builder()
		.method(method)
		.uri(path)
		.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
	let body = match body {
		Some(json) => {
			request = request.header(header::CONTENT_TYPE, "application/json");
			Body::from(json.to_string())
		}
		None => Body::empty(),
	};
	let response = crate::api::router(state.clone())
		.oneshot(request.body(body).expect("request"))
		.await
		.expect("response");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	let value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
		serde_json::Value::String(String::from_utf8_lossy(&bytes).into_owned())
	});
	(status, value)
}
