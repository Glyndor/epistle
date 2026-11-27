//! A server with keys of several reaches, and the keys the routes are tried
//! with.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use tower::ServiceExt;

use crate::api::ApiState;
use crate::api::api_keys::ApiKey;

/// `key`, `read`, `write`: no confinement.
pub(super) const MAKER: &str = "maker-secret";
/// `key`, `read`, confined to `a.example`.
pub(super) const MAKER_A: &str = "maker-a-secret";
/// `read` only.
pub(super) const PLAIN: &str = "plain-secret";
/// `key` and `read`, bound to an account.
pub(super) const BOUND: &str = "bound-secret";
/// Every scope, no confinement: more than any maker.
pub(super) const EVERYTHING: &str = "everything-secret";
/// `read`, confined to `b.example`.
pub(super) const OF_B: &str = "of-b-secret";
/// `read`, confined to `a.example`.
pub(super) const OF_A: &str = "of-a-secret";

pub(super) struct World {
	pub(super) dir: tempfile::TempDir,
	pub(super) state: ApiState,
}

pub(super) fn key(label: &str, secret: &str, scopes: &[&str], domains: &[&str]) -> ApiKey {
	ApiKey {
		label: label.to_string(),
		hash: crate::api::api_keys::sha256_hash(secret),
		expires_at: None,
		ip_cidr: None,
		scopes: scopes.iter().map(|scope| (*scope).to_string()).collect(),
		grants: Vec::new(),
		domains: domains.iter().map(|domain| (*domain).to_string()).collect(),
		account: None,
		auto_submitted: false,
	}
}

pub(super) fn world() -> World {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().canonicalize().expect("canonical");
	let mut bound = key("bound", BOUND, &["key", "read"], &[]);
	bound.account = Some("ann".to_string());
	let mut keys = crate::api::ApiKeyStore::open(&data_dir).expect("key store");
	for one in [
		key("maker", MAKER, &["key", "read", "write"], &[]),
		key("maker-a", MAKER_A, &["key", "read"], &["a.example"]),
		key("plain", PLAIN, &["read"], &[]),
		bound,
		key(
			"everything",
			EVERYTHING,
			&[
				"read", "write", "send", "scim", "alias", "ban", "health", "key",
			],
			&[],
		),
		key("of-b", OF_B, &["read"], &["b.example"]),
		key("of-a", OF_A, &["read"], &["a.example"]),
	] {
		keys.add(one).expect("add key");
	}
	drop(keys);
	let accounts = Arc::new(
		crate::directory_store::AccountStore::open(
			&data_dir,
			vec!["a.example".to_string(), "b.example".to_string()],
			HashMap::new(),
			vec![
				account("ann", "ann@a.example"),
				account("bob", "bob@b.example"),
			],
		)
		.expect("store"),
	);
	let keyset = Arc::new(crate::api::ApiKeySet::open(&data_dir).expect("key set"));
	let state = ApiState::new(
		&crate::smtp::auth::tests::base::hash(crate::api::tests::base::TOKEN.as_str()),
		data_dir.clone(),
		vec!["a.example".to_string(), "b.example".to_string()],
		accounts.clone(),
		crate::storage::FsSpool::open(&data_dir).expect("spool"),
	)
	.with_directory(accounts.handle())
	.with_api_keys(keyset);
	World { dir, state }
}

fn account(name: &str, address: &str) -> crate::config::Account {
	crate::config::Account {
		send: None,
		receive: None,
		display_name: None,
		name: name.to_string(),
		addresses: vec![address.to_string()],
		password_hash: Some("$argon2id$secret".to_string()),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
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
) -> (StatusCode, HeaderMap, serde_json::Value) {
	let mut request = Request::builder()
		.method(method)
		.uri(path)
		.extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
			[127, 0, 0, 1],
			40000,
		))))
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
	let (parts, body) = response.into_parts();
	let bytes = axum::body::to_bytes(body, usize::MAX).await.expect("body");
	let value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
		serde_json::Value::String(String::from_utf8_lossy(&bytes).into_owned())
	});
	(parts.status, parts.headers, value)
}

/// The keys of the file, by label.
pub(super) fn labels(world: &World) -> Vec<String> {
	let store = crate::api::ApiKeyStore::open(world.dir.path()).expect("open");
	let mut labels: Vec<String> = store.keys().iter().map(|key| key.label.clone()).collect();
	labels.sort();
	labels
}
