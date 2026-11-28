//! Two tenants with an account each, a third domain whose tenant holds one
//! account at most, a cap of four addresses an account and the keys the
//! address routes are tried with.

use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::{Layer, Registry};

use crate::api::ApiState;
use crate::api::api_keys::ApiKey;
use crate::directory_store::{AccountStore, DynamicAccount};

/// `manage:write`, confined to `a.test`.
pub(super) const OF_A: &str = "of-a-secret";
/// `manage:write`, confined to `b.test`.
pub(super) const OF_B: &str = "of-b-secret";
/// `manage:write`, no confinement.
pub(super) const WRITER: &str = "writer-secret";
/// `manage:read` only.
pub(super) const READER: &str = "reader-secret";
/// `manage:write`, bound to `alice`.
pub(super) const OF_ALICE: &str = "of-alice-secret";

pub(super) struct World {
	pub(super) dir: tempfile::TempDir,
	pub(super) state: ApiState,
	pub(super) store: Arc<AccountStore>,
}

pub(super) fn key(
	label: &str,
	secret: &str,
	scopes: &[&str],
	domains: &[&str],
	account: Option<&str>,
) -> ApiKey {
	ApiKey {
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

/// Hashed once: the tests build many worlds, and the hash is slow on purpose.
static PASSWORD_HASH: LazyLock<String> =
	LazyLock::new(|| crate::smtp::auth::tests::base::hash("a long enough password 1"));
static TOKEN_HASH: LazyLock<String> =
	LazyLock::new(|| crate::smtp::auth::tests::base::hash(token()));

pub(super) fn account(name: &str, addresses: &[&str]) -> DynamicAccount {
	DynamicAccount {
		name: name.to_string(),
		addresses: addresses.iter().map(|a| (*a).to_string()).collect(),
		password_hash: PASSWORD_HASH.clone(),
		..DynamicAccount::default()
	}
}

pub(super) fn domains() -> Vec<String> {
	vec![
		"a.test".to_string(),
		"b.test".to_string(),
		"c.test".to_string(),
	]
}

pub(super) fn world() -> World {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().canonicalize().expect("canonical");
	let store = Arc::new(
		AccountStore::open(
			&data_dir,
			domains(),
			std::collections::HashMap::new(),
			Vec::new(),
		)
		.expect("store")
		// `c.test` belongs to a tenant that holds one account at most.
		.with_limits(crate::limits::test_support::shared_from(
			"domains = [\"a.test\", \"b.test\", \"c.test\"]\n\
			 [limits]\nmax_addresses_per_account = 4\n\
			 [[tenant]]\nname = \"c\"\ndomains = [\"c.test\"]\nmax_accounts = 1\n",
		)),
	);
	store
		.add(account("alice", &["alice@a.test", "alice2@a.test"]))
		.expect("alice");
	store.add(account("bob", &["bob@b.test"])).expect("bob");
	// An account that belongs to two tenants at once.
	store
		.add(account("split", &["split@a.test", "split@b.test"]))
		.expect("split");
	let mut keys = crate::api::ApiKeyStore::open(&data_dir).expect("key store");
	for one in [
		key("of-a", OF_A, &["manage:write"], &["a.test"], None),
		key("of-b", OF_B, &["manage:write"], &["b.test"], None),
		key("writer", WRITER, &["manage:write"], &[], None),
		key("reader", READER, &["manage:read"], &[], None),
		key("of-alice", OF_ALICE, &["manage:write"], &[], Some("alice")),
	] {
		keys.add(one).expect("add key");
	}
	drop(keys);
	let keyset = Arc::new(crate::api::ApiKeySet::open(&data_dir).expect("key set"));
	let state = ApiState::new(
		&TOKEN_HASH,
		data_dir.clone(),
		domains(),
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
	body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
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
	let value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
		serde_json::Value::String(String::from_utf8_lossy(&bytes).into_owned())
	});
	(status, value)
}

/// The addresses of an account, sorted.
pub(super) fn addresses(world: &World, name: &str) -> Vec<String> {
	let mut held = world.store.dynamic(name).expect("account").addresses;
	held.sort();
	held
}

/// The audit events a request writes.
#[derive(Clone, Default)]
pub(super) struct Capture(Arc<Mutex<Vec<BTreeMap<String, String>>>>);

impl Capture {
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
