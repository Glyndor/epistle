//! A server hosting three domains, the keys the DNS routes are tried with,
//! and a resolver that records what it is asked.

use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use tower::ServiceExt;

use crate::api::ApiState;
use crate::config::Config;
use crate::spf::{DnsFailure, DnsLookup};

/// `read`, confined to `a.example`.
pub(super) const CONFINED: &str = "dns-confined-secret";
/// `read`, unconfined.
pub(super) const READER: &str = "dns-reader-secret";
/// `write` only, unconfined: a valid key without the scope a read needs.
pub(super) const WRITER: &str = "dns-writer-secret";
/// `send` only, unconfined.
pub(super) const SENDER: &str = "dns-sender-secret";
/// `read`, confined to a domain the server does not host.
pub(super) const ELSEWHERE: &str = "dns-elsewhere-secret";
/// `read`, bound to an account.
pub(super) const BOUND: &str = "dns-bound-secret";

/// The mail host of the fixture, whose records belong to no tenant.
pub(super) const HOST: &str = "mail.a.example";

type Lookup<'a, T> = Pin<Box<dyn Future<Output = Result<T, DnsFailure>> + Send + 'a>>;

/// A resolver with no records that notes every name it is asked about, and
/// can be told to hold every answer back.
#[derive(Default)]
pub(super) struct Recording {
	pub(super) asked: Mutex<Vec<String>>,
	/// While this has no permit, every lookup waits.
	pub(super) hold: Option<Arc<tokio::sync::Semaphore>>,
	pub(super) txt: HashMap<String, Vec<String>>,
}

impl Recording {
	fn note(&self, name: &str) {
		self.asked.lock().expect("asked").push(name.to_string());
	}

	async fn wait(&self) {
		if let Some(hold) = &self.hold {
			let _ = hold.acquire().await;
		}
	}

	pub(super) fn names(&self) -> Vec<String> {
		self.asked.lock().expect("asked").clone()
	}
}

impl DnsLookup for Recording {
	fn txt(&self, name: &str) -> Lookup<'_, Vec<String>> {
		self.note(name);
		let found = self.txt.get(name).cloned().unwrap_or_default();
		Box::pin(async move {
			self.wait().await;
			Ok(found)
		})
	}
	fn addresses(&self, name: &str) -> Lookup<'_, Vec<IpAddr>> {
		self.note(name);
		Box::pin(async move {
			self.wait().await;
			Ok(Vec::new())
		})
	}
	fn mx(&self, name: &str) -> Lookup<'_, Vec<String>> {
		self.note(name);
		Box::pin(async move {
			self.wait().await;
			Ok(Vec::new())
		})
	}
	fn ptr(&self, ip: IpAddr) -> Lookup<'_, Vec<String>> {
		self.note(&ip.to_string());
		Box::pin(async move {
			self.wait().await;
			Ok(Vec::new())
		})
	}
}

/// The configuration text of the server, with `extra` before its tables.
pub(super) fn config_text(data_dir: &std::path::Path, domains: &[String], extra: &str) -> String {
	format!(
		"hostname = '{HOST}'\n\
		 data_dir = {data_dir:?}\n\
		 domains = {domains:?}\n\
		 public_ipv4 = '192.0.2.10'\n\
		 {extra}\n"
	)
}

/// The three domains of the usual server.
pub(super) fn three() -> Vec<String> {
	["a.example", "b.example", "c.example"]
		.map(String::from)
		.to_vec()
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

pub(super) struct World {
	pub(super) _dir: tempfile::TempDir,
	pub(super) state: ApiState,
}

pub(super) fn world() -> World {
	world_with("", Arc::new(Recording::default()))
}

pub(super) fn world_with(extra: &str, dns: Arc<Recording>) -> World {
	build(&three(), extra, dns, true)
}

/// A server hosting `domains`, with or without the live configuration the
/// routes read.
pub(super) fn build(domains: &[String], extra: &str, dns: Arc<Recording>, live: bool) -> World {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().canonicalize().expect("canonical");
	let config: Config = toml::from_str(&config_text(&data_dir, domains, extra)).expect("config");
	let mut keys = crate::api::ApiKeyStore::open(&data_dir).expect("key store");
	let mut bound = key("bound", BOUND, &["read"], &[]);
	bound.account = Some("ann".to_string());
	for one in [
		key("confined", CONFINED, &["read"], &["a.example"]),
		key("reader", READER, &["read"], &[]),
		key("writer", WRITER, &["write"], &[]),
		key("sender", SENDER, &["send"], &[]),
		key("elsewhere", ELSEWHERE, &["read"], &["z.example"]),
		bound,
	] {
		keys.add(one).expect("add key");
	}
	drop(keys);
	let store = Arc::new(
		crate::directory_store::AccountStore::open(
			&data_dir,
			config.domains.clone(),
			HashMap::new(),
			Vec::new(),
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
	.with_dns_lookup(dns);
	let state = if live {
		state.with_live_domains(crate::editable::LiveConfig::new(config.clone()))
	} else {
		state
	};
	World { _dir: dir, state }
}

/// The configured token, which holds every scope and every domain.
pub(super) fn token() -> &'static str {
	crate::api::tests::base::TOKEN.as_str()
}

/// `GET path` with `token` through the whole router, middleware included.
pub(super) async fn get(world: &World, path: &str, token: &str) -> (StatusCode, serde_json::Value) {
	let (status, _, body) = get_with_headers(&world.state, path, Some(token)).await;
	(status, body)
}

pub(super) async fn get_with_headers(
	state: &ApiState,
	path: &str,
	token: Option<&str>,
) -> (StatusCode, HeaderMap, serde_json::Value) {
	let app = crate::api::router(state.clone());
	let mut request = Request::builder().uri(path);
	if let Some(token) = token {
		request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
	}
	let response = app
		.oneshot(request.body(Body::empty()).expect("request"))
		.await
		.expect("response");
	let (parts, body) = response.into_parts();
	let bytes = axum::body::to_bytes(body, usize::MAX).await.expect("body");
	let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
	(parts.status, parts.headers, value)
}
