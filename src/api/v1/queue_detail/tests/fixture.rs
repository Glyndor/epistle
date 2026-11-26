//! A server with two tenants' messages in the queue, and the keys the queue
//! routes are tried with.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;
use uuid::Uuid;

use crate::api::ApiState;
use crate::smtp::session::AcceptedMessage;

/// `read` and `write`, confined to `a.example`.
pub(super) const TENANT_A: &str = "queue-tenant-a-secret";
/// `read`, unconfined.
pub(super) const READER: &str = "queue-reader-secret";
/// `write`, unconfined.
pub(super) const WRITER: &str = "queue-writer-secret";
/// `read` and `write`, bound to an account.
pub(super) const BOUND: &str = "queue-bound-secret";

pub(super) const MESSAGE: &str = "Subject: quarterly figures\r\nFrom: <ann@a.example>\r\nTo: bob@remote.example\r\nReceived: from here\r\n by there; Tue, 24 Nov 2026 10:00:00 +0000\r\nX-Folded: one\r\n two\r\n\tthree\r\n\r\ntop secret body text\r\n";

pub(super) struct World {
	pub(super) _dir: tempfile::TempDir,
	pub(super) state: ApiState,
	/// The entry of `ann@a.example`.
	pub(super) mine: Uuid,
	/// The entry of `bea@b.example`.
	pub(super) theirs: Uuid,
	/// Written by a stranger with `ann@a.example` as its sender; no owner.
	pub(super) spoofed: Uuid,
	/// Written with `ann@a.example` as its sender, owned by `b.example`.
	pub(super) misowned: Uuid,
	/// A forward without SRS: the sender is outside, the owner is `a.example`.
	pub(super) forward: Uuid,
	/// A forward with SRS.
	pub(super) forward_srs: Uuid,
	/// A return: no sender, the owner is `a.example`.
	pub(super) bounce: Uuid,
	/// A return whose sender is an SRS address of `b.example`, owned by `a.example`.
	pub(super) srs_bounce: Uuid,
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

fn queue(spool: &crate::storage::FsSpool, from: &str, owner: Option<&str>, data: &str) -> Uuid {
	spool
		.store_owned(
			&AcceptedMessage {
				reverse_path: from.to_string(),
				recipients: vec!["bob@remote.example".to_string()],
				data: data.as_bytes().to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: false,
				no_dsn: Vec::new(),
			},
			owner,
			&BTreeMap::new(),
		)
		.expect("store")
}

pub(super) fn world() -> World {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().canonicalize().expect("canonical");
	let spool = crate::storage::FsSpool::open(&data_dir).expect("spool");
	let mine = queue(&spool, "ann@a.example", Some("a.example"), MESSAGE);
	let theirs = queue(&spool, "bea@b.example", Some("b.example"), MESSAGE);
	let spoofed = queue(&spool, "ann@a.example", None, MESSAGE);
	let misowned = queue(&spool, "ann@a.example", Some("b.example"), MESSAGE);
	let forward = queue(&spool, "carl@elsewhere.example", Some("a.example"), MESSAGE);
	let forward_srs = queue(
		&spool,
		"SRS0=HHH=TT=elsewhere.example=carl@a.example",
		Some("a.example"),
		MESSAGE,
	);
	let bounce = queue(&spool, "", Some("a.example"), MESSAGE);
	let srs_bounce = queue(
		&spool,
		"SRS0=HHH=TT=b.example=bea@b.example",
		Some("a.example"),
		MESSAGE,
	);
	let mut keys = crate::api::ApiKeyStore::open(&data_dir).expect("key store");
	let mut bound = key("bound", BOUND, &["read", "write"], &[]);
	bound.account = Some("ann".to_string());
	for one in [
		key("tenant-a", TENANT_A, &["read", "write"], &["a.example"]),
		key("reader", READER, &["read"], &[]),
		key("writer", WRITER, &["write"], &[]),
		bound,
	] {
		keys.add(one).expect("add key");
	}
	drop(keys);
	let accounts = Arc::new(
		crate::directory_store::AccountStore::open(
			&data_dir,
			vec!["a.example".to_string(), "b.example".to_string()],
			HashMap::new(),
			Vec::new(),
		)
		.expect("store"),
	);
	let state = ApiState::new(
		&crate::smtp::auth::tests::base::hash(crate::api::tests::base::TOKEN.as_str()),
		data_dir.clone(),
		vec!["a.example".to_string(), "b.example".to_string()],
		accounts.clone(),
		spool,
	)
	.with_directory(accounts.handle());
	World {
		_dir: dir,
		state,
		mine,
		theirs,
		spoofed,
		misowned,
		forward,
		forward_srs,
		bounce,
		srs_bounce,
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
) -> (StatusCode, serde_json::Value) {
	let request = Request::builder()
		.method(method)
		.uri(path)
		.header(header::AUTHORIZATION, format!("Bearer {bearer}"))
		.body(Body::empty())
		.expect("request");
	let response = crate::api::router(state.clone())
		.oneshot(request)
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
