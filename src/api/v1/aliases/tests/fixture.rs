//! A server hosting two domains with accounts in each, one alias of its own,
//! read from a real configuration file, and the keys the alias routes are
//! tried with.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use axum::http::StatusCode;
use serde_json::Value;

use crate::api::ApiState;
use crate::config::Config;
use crate::domain::catalog::Catalog;

/// `alias`, confined to `a.example`.
pub(super) const TENANT_A: &str = "alias-tenant-a-secret";
/// `alias`, confined to `b.example`.
pub(super) const TENANT_B: &str = "alias-tenant-b-secret";
/// `alias`, not confined.
pub(super) const ALL: &str = "alias-everywhere-secret";
/// `read` and `write`, not confined: every scope but the one that matters.
pub(super) const READ_WRITE: &str = "read-write-secret";
/// `alias` and `read`, confined to a domain the server does not host.
/// `alias`, confined to `bücher.example` written as Unicode.
pub(super) const IDN_UNICODE: &str = "alias-idn-unicode-secret";
/// `alias`, confined to the same domain written as `xn--bcher-kva.example`.
pub(super) const IDN_ASCII: &str = "alias-idn-ascii-secret";
pub(super) const ELSEWHERE: &str = "alias-elsewhere-secret";
/// `alias`, not confined, expired.
pub(super) const EXPIRED: &str = "alias-expired-secret";
/// `alias`, bound to the account `ann`.
pub(super) const BOUND: &str = "alias-bound-secret";

pub(super) const HASH: &str = "$argon2id$v=19$m=65536,t=2,p=1$YWFhYWFhYWFhYWFhYWFhYQ$0000000000000000000000000000000000000000000";

fn config_text(data_dir: &std::path::Path, extra: &str) -> String {
	format!(
		"hostname = \"mail.a.example\"\n\
		 data_dir = {data_dir:?}\n\
		 domains = [\"a.example\", \"b.example\", \"xn--bcher-kva.example\"]\n\
		 {extra}\n\
		 [domain_aliases]\n\
		 \"alias.example\" = \"a.example\"\n\
		 \n\
		 [[accounts]]\n\
		 name = \"ann\"\n\
		 addresses = [\"ann@a.example\"]\n\
		 password_hash = \"{HASH}\"\n\
		 \n\
		 [[accounts]]\n\
		 name = \"abe\"\n\
		 addresses = [\"abe@a.example\"]\n\
		 password_hash = \"{HASH}\"\n\
		 \n\
		 [[accounts]]\n\
		 name = \"ida\"\n\
		 addresses = [\"ida@xn--bcher-kva.example\"]\n\
		 password_hash = \"{HASH}\"\n\
		 \n\
		 [[accounts]]\n\
		 name = \"bob\"\n\
		 addresses = [\"bob@b.example\"]\n\
		 password_hash = \"{HASH}\"\n\
		 \n\
		 [[alias]]\n\
		 address = \"team@a.example\"\n\
		 members = [\"ann@a.example\"]\n\
		 \n\
		 [[alias]]\n\
		 address = \"crew@b.example\"\n\
		 members = [\"bob@b.example\"]\n"
	)
}

pub(super) struct World {
	pub(super) _dir: tempfile::TempDir,
	pub(super) state: ApiState,
}

impl World {
	pub(super) fn data_dir(&self) -> &std::path::Path {
		self.state.data_dir()
	}

	pub(super) fn config_path(&self) -> std::path::PathBuf {
		self._dir.path().canonicalize().unwrap().join("mail.toml")
	}

	/// The state file as it is on disk, `None` while nobody wrote it.
	pub(super) fn disk(&self) -> Option<crate::aliases::AliasesFile> {
		crate::aliases::AliasesFile::read(&crate::aliases::path(self.data_dir())).unwrap()
	}
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
		domains: domains.iter().map(|domain| (*domain).to_string()).collect(),
		account: None,
		auto_submitted: false,
	}
}

pub(super) fn world() -> World {
	world_with("")
}

pub(super) fn world_with(extra: &str) -> World {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().canonicalize().expect("canonical");
	let path = data_dir.join("mail.toml");
	let mut file = std::fs::OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(&path)
		.expect("config file");
	file.write_all(config_text(&data_dir, extra).as_bytes())
		.expect("write config");
	drop(file);
	let config = Config::load(&path).expect("config loads");
	let mut keys = crate::api::ApiKeyStore::open(&data_dir).expect("key store");
	let mut expired = key("expired", EXPIRED, &["alias"], &[]);
	expired.expires_at = Some(1);
	let mut bound = key("bound", BOUND, &["alias"], &[]);
	bound.account = Some("ann".to_string());
	for one in [
		key("tenant-a", TENANT_A, &["alias"], &["a.example"]),
		key("tenant-b", TENANT_B, &["alias"], &["b.example"]),
		key("all", ALL, &["alias"], &[]),
		key("read-write", READ_WRITE, &["read", "write"], &[]),
		key(
			"idn-unicode",
			IDN_UNICODE,
			&["alias"],
			&["b\u{fc}cher.example"],
		),
		key(
			"idn-ascii",
			IDN_ASCII,
			&["alias"],
			&["xn--bcher-kva.example"],
		),
		key("elsewhere", ELSEWHERE, &["alias", "read"], &["c.example"]),
		expired,
		bound,
	] {
		keys.add(one).expect("add key");
	}
	drop(keys);
	let store = std::sync::Arc::new(
		crate::directory_store::AccountStore::open(
			&data_dir,
			config.domains.clone(),
			std::collections::HashMap::new(),
			config.accounts.clone(),
		)
		.expect("store"),
	);
	let state = ApiState::new(
		&crate::smtp::auth::tests::base::hash(crate::api::tests::base::TOKEN.as_str()),
		data_dir.clone(),
		config.domains.clone(),
		store.clone(),
		crate::storage::FsSpool::open(&data_dir).expect("spool"),
	)
	.with_directory(store.handle())
	.with_domain_catalog(Catalog::from_config(&config));
	let state = state.with_live_domains(crate::editable::LiveConfig::new(config));
	World { _dir: dir, state }
}

/// One request through the whole router, middleware included.
pub(super) async fn call(
	world: &World,
	method: &str,
	path: &str,
	key: &str,
	body: Option<Value>,
) -> (StatusCode, Value) {
	crate::api::tests::base::request_with_body(
		&crate::api::router(world.state.clone()),
		method,
		path,
		Some(key),
		body,
	)
	.await
}

/// The configured token, which holds every scope and every domain.
pub(super) fn token() -> &'static str {
	crate::api::tests::base::TOKEN.as_str()
}

/// The addresses of the aliases in a listing.
pub(super) fn addresses(body: &Value) -> Vec<String> {
	body["aliases"]
		.as_array()
		.expect("aliases")
		.iter()
		.map(|row| row["address"].as_str().expect("address").to_string())
		.collect()
}

/// A request with a body that is text and not JSON, for the answers that
/// are not an API error body: only the status and the bytes come back.
pub(super) async fn call_text(
	world: &World,
	method: &str,
	path: &str,
	key: &str,
	body: String,
) -> (StatusCode, Vec<u8>) {
	let (status, _, bytes) = call_full(world, method, path, key, body).await;
	(status, bytes)
}

/// Status, headers and body bytes of one request, for comparing two answers
/// as a client would see them. The headers whose value changes with every
/// answer are left out.
pub(super) async fn call_full(
	world: &World,
	method: &str,
	path: &str,
	key: &str,
	body: String,
) -> (StatusCode, Vec<(String, String)>, Vec<u8>) {
	use axum::body::Body;
	use axum::http::{Request, header};
	use tower::ServiceExt;
	let app = crate::api::router(world.state.clone());
	let request = Request::builder()
		.method(method)
		.uri(path)
		.header(header::AUTHORIZATION, format!("Bearer {key}"))
		.header(header::CONTENT_TYPE, "application/json")
		.body(Body::from(body))
		.expect("request");
	let response = app.oneshot(request).await.expect("response");
	let status = response.status();
	let mut headers: Vec<(String, String)> = response
		.headers()
		.iter()
		.filter(|(name, _)| !matches!(name.as_str(), "date" | "x-request-id"))
		.map(|(name, value)| (name.to_string(), value.to_str().unwrap_or("?").to_string()))
		.collect();
	headers.sort();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	(status, headers, bytes.to_vec())
}
