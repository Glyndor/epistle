//! A credential is asked about again at the point a write is made: under the
//! account store's lock, after the body has arrived and any password has been
//! derived. The tests hold that lock, wait until the request is stopped at it,
//! change the key and let go.

use std::path::Path;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;
use tracing::instrument::WithSubscriber;

use super::super::base::test_state;
use super::*;
use crate::directory_store::DynamicAccount;

const SECRET: &str = "held-commit-secret";
const PRIOR: &str = "$argon2id$prior";
const PRIOR_QUOTA: u64 = 4096;

fn state_with(dir: &Path, scope: &str) -> crate::api::ApiState {
	let state = test_state(dir, 0);
	state
		.store()
		.add(DynamicAccount {
			name: "dyna".to_string(),
			addresses: vec!["dyna@example.org".to_string()],
			password_hash: PRIOR.to_string(),
			quota_bytes: Some(PRIOR_QUOTA),
			..DynamicAccount::default()
		})
		.expect("add dyna");
	let mut keys = crate::api::ApiKeyStore::open(dir).expect("key store");
	keys.add(crate::api::api_keys::ApiKey {
		label: "k".to_string(),
		hash: crate::api::api_keys::sha256_hash(SECRET),
		expires_at: None,
		ip_cidr: None,
		scopes: vec![scope.to_string()],
		grants: Vec::new(),
		domains: Vec::new(),
		account: None,
		auto_submitted: false,
	})
	.expect("add key");
	drop(keys);
	reload(&state, dir);
	state
}

fn reload(state: &crate::api::ApiState, dir: &Path) {
	let text = std::fs::read_to_string(dir.join("api_keys.toml")).expect("key file");
	state.api_keys().reload_from(&text).expect("reload keys");
}

fn revoke(state: &crate::api::ApiState, dir: &Path) {
	let mut keys = crate::api::ApiKeyStore::open(dir).expect("key store");
	keys.remove("k").expect("remove key");
	reload(state, dir);
}

/// Wait until some thread is queued on the lock of the file at `lock`, as the
/// kernel lists it.
pub(super) async fn until_waiting(lock: &Path) {
	use std::os::unix::fs::MetadataExt;
	let inode = format!(":{}", std::fs::metadata(lock).expect("lock file").ino());
	for _ in 0..18_000 {
		let locks = std::fs::read_to_string("/proc/locks").expect("/proc/locks");
		if locks.lines().any(|line| {
			line.contains("->") && line.split_whitespace().any(|field| field.ends_with(&inode))
		}) {
			return;
		}
		tokio::time::sleep(Duration::from_millis(10)).await;
	}
	panic!("the request never reached the account store's lock");
}

/// Send `method` `path` with `payload`, hold it at the account store's lock,
/// run `change`, let it go; the status it answered.
async fn held_request(
	state: &crate::api::ApiState,
	method: &str,
	path: &str,
	payload: Value,
	change: impl FnOnce(),
) -> StatusCode {
	let request = Request::builder()
		.method(method)
		.uri(path)
		.header(header::AUTHORIZATION, format!("Bearer {SECRET}"))
		.header(header::CONTENT_TYPE, "application/json")
		.body(Body::from(payload.to_string()))
		.expect("request");
	held_at_the_lock(state, request, change).await
}

/// [`held_request`] for a request the caller has built.
pub(super) async fn held_at_the_lock(
	state: &crate::api::ApiState,
	request: Request<Body>,
	change: impl FnOnce(),
) -> StatusCode {
	let lock = crate::storage::locked::lock_path(state.store().store_path());
	let held = crate::storage::lock::FileLock::acquire(&lock).expect("hold the lock");
	let app = router(state.clone());
	// The request runs on a task of its own and keeps the caller's subscriber.
	let answer = tokio::spawn(
		async move { app.oneshot(request).await.expect("response") }.with_current_subscriber(),
	);
	until_waiting(&lock).await;
	change();
	drop(held);
	answer.await.expect("the request task").status()
}

fn password() -> &'static str {
	crate::test_support::fixtures::second_password()
}

/// The writes of a request that wait for the account store's lock, with the
/// scope each needs and the account it is about.
fn writes() -> Vec<(
	&'static str,
	&'static str,
	&'static str,
	&'static str,
	Value,
)> {
	vec![
		(
			"password",
			"manage:write",
			"PUT",
			"/api/v1/accounts/dyna/password",
			json!({ "password": password() }),
		),
		(
			"create",
			"manage:write",
			"POST",
			"/api/v1/accounts",
			json!({ "name": "newbie", "addresses": ["newbie@example.org"], "password": password() }),
		),
		(
			"quota set",
			"manage:write",
			"PUT",
			"/api/v1/accounts/dyna/quota",
			json!({ "quota": "2G" }),
		),
		(
			"quota clear",
			"manage:write",
			"DELETE",
			"/api/v1/accounts/dyna/quota",
			Value::Null,
		),
		(
			"SCIM patch",
			"scim",
			"PATCH",
			"/scim/v2/Users/dyna",
			json!({
				"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				"Operations": [{"op": "replace", "path": "password", "value": password()}],
			}),
		),
		(
			"SCIM put",
			"scim",
			"PUT",
			"/scim/v2/Users/dyna",
			json!({
				"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
				"userName": "dyna",
				"active": false,
				"emails": [{"value": "dyna@example.org"}],
				"password": password(),
			}),
		),
		(
			"SCIM create",
			"scim",
			"POST",
			"/scim/v2/Users",
			json!({
				"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
				"userName": "newbie",
				"active": true,
				"emails": [{"value": "newbie@example.org"}],
				"password": password(),
			}),
		),
	]
}

fn unchanged(state: &crate::api::ApiState) -> bool {
	let dyna = state.store().dynamic_account("dyna").expect("dyna");
	dyna.password_hash == PRIOR
		&& !dyna.disabled
		&& dyna.quota_bytes == Some(PRIOR_QUOTA)
		&& state.store().dynamic("newbie").is_none()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_revoked_before_the_write_stops_it() {
	// Every write is tried before judging, so a failure names all that went on.
	let mut went_on = Vec::new();
	for (name, scope, method, path, payload) in writes() {
		let dir = tempfile::tempdir().expect("tempdir");
		let state = state_with(dir.path(), scope);
		let status =
			held_request(&state, method, path, payload, || revoke(&state, dir.path())).await;
		if status.is_success() || !unchanged(&state) {
			went_on.push(format!("{name}: {status}"));
		}
	}
	assert!(went_on.is_empty(), "writes that went on: {went_on:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_left_alone_writes_after_waiting_for_the_lock() {
	for (name, scope, method, path, payload) in writes() {
		let dir = tempfile::tempdir().expect("tempdir");
		let state = state_with(dir.path(), scope);
		let status = held_request(&state, method, path, payload, || {}).await;
		assert!(status.is_success(), "{name}: {status}");
		assert!(!unchanged(&state), "{name}: it was written");
	}
}
