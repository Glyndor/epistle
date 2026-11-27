//! Two tenants, the keys the routes are tried with, and a way to change a key
//! or the account file while a write waits for that file's lock.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::Value;
use tower::ServiceExt;
use tracing::field::{Field, Visit};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::{Layer, Registry};

use crate::api::ApiState;
use crate::api::api_keys::ApiKey;
use crate::directory_store::{AccountStore, DynamicAccount};
use crate::storage::lock::{FileLock, reached};

/// `manage:write`, confined to `a.test`.
pub(super) const OF_A: &str = "of-a-secret";
/// `manage:write`, confined to `b.test`.
pub(super) const OF_B: &str = "of-b-secret";
/// `manage:write`, no confinement.
pub(super) const WRITER: &str = "writer-secret";
/// `manage:read` only.
pub(super) const READER: &str = "reader-secret";
/// `write`, bound to `alice`.
pub(super) const OF_ALICE: &str = "of-alice-secret";

pub(super) const PASSWORD: &str = "a long enough password 1";

pub(super) struct World {
	pub(super) dir: tempfile::TempDir,
	pub(super) state: ApiState,
	pub(super) store: Arc<AccountStore>,
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

fn account(name: &str, addresses: &[&str]) -> DynamicAccount {
	DynamicAccount {
		name: name.to_string(),
		addresses: addresses.iter().map(|a| (*a).to_string()).collect(),
		password_hash: crate::smtp::auth::tests::base::hash(PASSWORD),
		..DynamicAccount::default()
	}
}

/// `alice` in `a.test`, `bob` in `b.test`, `split` in both, and `carol`, an
/// account of the configuration file.
pub(super) fn world() -> World {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().canonicalize().expect("canonical");
	let domains = vec!["a.test".to_string(), "b.test".to_string()];
	let carol = crate::config::Account {
		send: None,
		receive: None,
		display_name: None,
		name: "carol".to_string(),
		addresses: vec!["carol@a.test".to_string()],
		password_hash: Some("$argon2id$secret".to_string()),
		catch_all: Vec::new(),
		quota_bytes: None,
		forward: Vec::new(),
		forward_keep_local: true,
		allowed_protocols: None,
	};
	let store = Arc::new(
		AccountStore::open(
			&data_dir,
			domains.clone(),
			std::collections::HashMap::new(),
			vec![carol],
		)
		.expect("store"),
	);
	store
		.add(account("alice", &["alice@a.test"]))
		.expect("alice");
	store.add(account("bob", &["bob@b.test"])).expect("bob");
	store
		.add(account("split", &["split@a.test", "split@b.test"]))
		.expect("split");
	let mut keys = crate::api::ApiKeyStore::open(&data_dir).expect("key store");
	let mut bound = key("of-alice", OF_ALICE, &["write"], &[]);
	bound.account = Some("alice".to_string());
	for one in [
		key("of-a", OF_A, &["manage:write"], &["a.test"]),
		key("of-b", OF_B, &["manage:write"], &["b.test"]),
		key("writer", WRITER, &["manage:write"], &[]),
		key("reader", READER, &["manage:read"], &[]),
		bound,
	] {
		keys.add(one).expect("add key");
	}
	drop(keys);
	let keyset = Arc::new(crate::api::ApiKeySet::open(&data_dir).expect("key set"));
	let state = ApiState::new(
		&crate::smtp::auth::tests::base::hash(token()),
		data_dir.clone(),
		domains,
		store.clone(),
		crate::storage::FsSpool::open(&data_dir).expect("spool"),
	)
	.with_directory(store.handle())
	.with_api_keys(keyset);
	World { dir, state, store }
}

pub(super) fn token() -> &'static str {
	crate::api::tests::base::TOKEN.as_str()
}

/// `method path` for `bearer`, from `127.0.0.1`.
pub(super) async fn call(
	state: &ApiState,
	method: &str,
	path: &str,
	bearer: &str,
	body: Option<Value>,
) -> (StatusCode, Value) {
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
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	let value = serde_json::from_slice(&bytes)
		.unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
	(status, value)
}

pub(super) async fn post(
	world: &World,
	bearer: &str,
	name: &str,
	verb: &str,
) -> (StatusCode, Value) {
	let path = format!("/api/v1/accounts/{name}/{verb}");
	call(&world.state, "POST", &path, bearer, None).await
}

pub(super) fn disabled(world: &World, name: &str) -> bool {
	world.store.is_disabled(name)
}

/// Replace the key labelled as `now` in the file with `now`, or drop it when
/// there is no replacement, and load the file as the watcher does.
pub(super) fn replace_key(world: &World, label: &str, now: Option<ApiKey>) {
	let data_dir = world.dir.path();
	let mut keys = crate::api::ApiKeyStore::open(data_dir).expect("key store");
	keys.remove(label).expect("remove key");
	if let Some(now) = now {
		keys.add(now).expect("add key");
	}
	let text = std::fs::read_to_string(data_dir.join("api_keys.toml")).expect("key file");
	world.state.api_keys().reload_from(&text).expect("reload");
}

/// Change the row of `name` in the account file only: what the server holds in
/// memory stays as it was until a write reads the file again.
pub(super) fn edit_on_disk(world: &World, name: &str, field: &str, value: toml::Value) {
	let path = world.store.store_path();
	let text = std::fs::read_to_string(path).expect("account file");
	let mut file: toml::Table = toml::from_str(&text).expect("account toml");
	let row = file["accounts"]
		.as_array_mut()
		.expect("accounts")
		.iter_mut()
		.find(|row| row["name"].as_str() == Some(name))
		.expect("row");
	row.as_table_mut()
		.expect("table")
		.insert(field.to_string(), value);
	std::fs::write(path, toml::to_string(&file).expect("serialize")).expect("write");
}

#[derive(Clone, Default)]
pub(super) struct Capture(Arc<Mutex<Vec<BTreeMap<String, String>>>>);

impl Capture {
	/// The audit events seen so far.
	pub(super) fn events(&self) -> Vec<BTreeMap<String, String>> {
		self.0.lock().expect("capture").clone()
	}

	pub(super) fn kinds(&self) -> Vec<String> {
		self.events()
			.iter()
			.map(|event| event.get("event").cloned().unwrap_or_default())
			.collect()
	}

	pub(super) fn dispatch(&self) -> tracing::Dispatch {
		crate::cli::trace::capture::keep_callsites_live();
		tracing::Dispatch::new(Registry::default().with(self.clone()))
	}
}

#[derive(Default)]
struct Fields(BTreeMap<String, String>);

impl Visit for Fields {
	fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
		self.0.insert(field.name().into(), format!("{value:?}"));
	}

	fn record_str(&mut self, field: &Field, value: &str) {
		self.0.insert(field.name().into(), value.into());
	}
}

impl<S: tracing::Subscriber> Layer<S> for Capture {
	fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
		if event.metadata().target() == "epistle::api::audit" {
			let mut fields = Fields::default();
			event.record(&mut fields);
			self.0.lock().expect("capture").push(fields.0);
		}
	}
}

/// Send `method path` for `bearer`, and run `change` once the request has
/// passed every check made before the write and is waiting for the account
/// file's lock, which this holds until `change` is done. Nothing here waits
/// for a time to pass; the deadlines only turn a hang into a failure.
pub(super) async fn while_the_write_waits(
	world: &World,
	method: &'static str,
	path: &str,
	bearer: &'static str,
	change: impl FnOnce(),
) -> (StatusCode, Value, Capture) {
	let deadline = std::time::Duration::from_secs(60);
	let capture = Capture::default();
	let lock = crate::storage::locked::lock_path(world.store.store_path());
	let held = FileLock::acquire(&lock).expect("lock");
	let asked = reached::watch(&lock);
	let state = world.state.clone();
	let path = path.to_string();
	let request = tokio::spawn(
		async move { call(&state, method, &path, bearer, None).await }
			.with_subscriber(capture.dispatch()),
	);
	tokio::time::timeout(deadline, asked.acquire())
		.await
		.expect("the write never asked for the lock")
		.expect("open")
		.forget();
	change();
	drop(held);
	let (status, body) = tokio::time::timeout(deadline, request)
		.await
		.expect("the request never ended")
		.expect("request task");
	(status, body, capture)
}
