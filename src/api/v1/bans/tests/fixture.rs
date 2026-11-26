//! A server with a ban store in memory, and the keys the ban routes are
//! tried with.

use std::collections::HashMap;
use std::sync::Arc;

use axum::http::StatusCode;

use crate::antispam::bans::operator::tests::fake::FakeAdmin;
use crate::api::ApiState;

/// `ban`, unconfined: the key the routes are for.
pub(super) const BANNER: &str = "ban-key-secret";
/// `ban`, confined to a domain: a key the ban routes refuse.
pub(super) const CONFINED: &str = "ban-confined-secret";
/// `ban`, bound to an account.
pub(super) const BOUND: &str = "ban-bound-secret";
/// `read`, `write`, `send`, `alias` and `scim`, never `ban`.
pub(super) const OTHERS: &str = "everything-but-ban-secret";
/// `read` only.
pub(super) const READER: &str = "ban-reader-secret";

pub(super) struct World {
	pub(super) _dir: tempfile::TempDir,
	pub(super) state: ApiState,
	pub(super) store: Arc<FakeAdmin>,
}

fn key(
	label: &str,
	secret: &str,
	scopes: &[&str],
	domains: &[&str],
) -> crate::api::api_keys::ApiKey {
	crate::api::api_keys::ApiKey {
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
	build(Arc::new(FakeAdmin::default()), true)
}

/// A server on `store`, with the ban routes wired or not.
pub(super) fn build(store: Arc<FakeAdmin>, wired: bool) -> World {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().canonicalize().expect("canonical");
	let mut keys = crate::api::ApiKeyStore::open(&data_dir).expect("key store");
	let mut bound = key("bound", BOUND, &["ban"], &[]);
	bound.account = Some("ann".to_string());
	for one in [
		key("banner", BANNER, &["ban"], &[]),
		key("confined", CONFINED, &["ban"], &["a.example"]),
		key(
			"others",
			OTHERS,
			&["read", "write", "send", "alias", "scim"],
			&[],
		),
		key("reader", READER, &["read"], &[]),
		bound,
	] {
		keys.add(one).expect("add key");
	}
	drop(keys);
	let accounts = Arc::new(
		crate::directory_store::AccountStore::open(
			&data_dir,
			vec!["a.example".to_string()],
			HashMap::new(),
			Vec::new(),
		)
		.expect("store"),
	);
	let state = ApiState::new(
		&crate::smtp::auth::tests::base::hash(crate::api::tests::base::TOKEN.as_str()),
		data_dir.clone(),
		vec!["a.example".to_string()],
		accounts.clone(),
		crate::storage::FsSpool::open(&data_dir).expect("spool"),
	)
	.with_directory(accounts.handle());
	let state = if wired {
		state.with_ban_admin(store.clone())
	} else {
		state
	};
	World {
		_dir: dir,
		state,
		store,
	}
}

/// The configured token, which holds every scope and every domain.
pub(super) fn token() -> &'static str {
	crate::api::tests::base::TOKEN.as_str()
}

/// One request through the whole router, middleware included.
pub(super) async fn call(
	world: &World,
	method: &str,
	path: &str,
	bearer: &str,
	body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
	use tower::ServiceExt;
	let app = crate::api::router(world.state.clone());
	let mut request = axum::http::Request::builder()
		.method(method)
		.uri(path)
		.header("authorization", format!("Bearer {bearer}"));
	let body = match body {
		Some(json) => {
			request = request.header("content-type", "application/json");
			axum::body::Body::from(json.to_string())
		}
		None => axum::body::Body::empty(),
	};
	let response = app
		.oneshot(request.body(body).expect("request"))
		.await
		.expect("response");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	// A body the HTTP layer refuses is plain text, not the API's JSON.
	let value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
		serde_json::Value::String(String::from_utf8_lossy(&bytes).into_owned())
	});
	(status, value)
}
