//! The blob routes ask again about the credential and the account once they
//! have waited: an upload when its body is complete, before it stores
//! anything, and a download when the blob store has answered, before it hands
//! the bytes over.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;
use uuid::Uuid;

use super::*;
use crate::directory_store::{AccountStore, DynamicAccount};
use crate::storage::{BlobAccount, BlobBackend, BlobError, FsSpool};

const BOUND: &str = "blob-bound-secret";
const CONFINED: &str = "blob-confined-secret";
const PAYLOAD: &[u8] = b"payload that must stay with its tenant";

type Wait<'a, T> = Pin<Box<dyn Future<Output = Result<T, BlobError>> + Send + 'a>>;

/// The blob store, which can hold back the read of a payload.
struct Gate {
	inner: Arc<dyn BlobBackend>,
	armed: AtomicBool,
	entered: tokio::sync::Notify,
	release: tokio::sync::Semaphore,
}

impl BlobBackend for Gate {
	fn get(&self, account: &BlobAccount, id: Uuid, suffix: &str) -> Wait<'_, Option<Vec<u8>>> {
		let held = suffix.is_empty() && self.armed.load(Ordering::SeqCst);
		let read = self.inner.get(account, id, suffix);
		Box::pin(async move {
			if held {
				self.entered.notify_one();
				let _permit = self.release.acquire().await;
			}
			read.await
		})
	}

	fn put(&self, account: &BlobAccount, id: Uuid, suffix: &str, bytes: &[u8]) -> Wait<'_, ()> {
		self.inner.put(account, id, suffix, bytes)
	}

	fn delete(&self, account: &BlobAccount, id: Uuid, suffix: &str) -> Wait<'_, ()> {
		self.inner.delete(account, id, suffix)
	}

	fn list(&self) -> Wait<'_, Vec<Uuid>> {
		self.inner.list()
	}
}

struct World {
	dir: tempfile::TempDir,
	state: ApiState,
	store: Arc<AccountStore>,
	gate: Arc<Gate>,
}

fn key(
	label: &str,
	secret: &str,
	domains: &[&str],
	account: Option<&str>,
) -> crate::api::api_keys::ApiKey {
	crate::api::api_keys::ApiKey {
		grants: Vec::new(),
		label: label.to_string(),
		hash: crate::api::api_keys::sha256_hash(secret),
		expires_at: None,
		ip_cidr: None,
		scopes: vec!["read".to_string(), "write".to_string()],
		domains: domains.iter().map(|d| (*d).to_string()).collect(),
		account: account.map(str::to_string),
		auto_submitted: false,
	}
}

/// `carol` in `example.org`, a key bound to her and one confined to that
/// domain, with the gate in front of the blob store.
fn world() -> World {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut keys = crate::api::ApiKeyStore::open(dir.path()).expect("key store");
	keys.add(key("bound", BOUND, &[], Some("carol")))
		.expect("add bound");
	keys.add(key("confined", CONFINED, &["example.org"], None))
		.expect("add confined");
	drop(keys);
	let domains = vec!["example.org".to_string(), "other.example".to_string()];
	let store = Arc::new(
		AccountStore::open(
			dir.path(),
			domains.clone(),
			std::collections::HashMap::new(),
			Vec::new(),
		)
		.expect("open store"),
	);
	store
		.add(DynamicAccount {
			name: "carol".to_string(),
			addresses: vec!["carol@example.org".to_string()],
			password_hash: "$argon2id$secret".to_string(),
			..DynamicAccount::default()
		})
		.expect("add carol");
	let state = ApiState::new(
		&crate::smtp::auth::tests::base::hash(super::super::base::TOKEN.as_str()),
		dir.path().to_path_buf(),
		domains,
		store.clone(),
		FsSpool::open(dir.path()).expect("open spool"),
	)
	.with_directory(store.handle());
	let gate = Arc::new(Gate {
		inner: Arc::clone(state.blob_backend()),
		armed: AtomicBool::new(false),
		entered: tokio::sync::Notify::new(),
		release: tokio::sync::Semaphore::new(0),
	});
	let backend: Arc<dyn BlobBackend> = gate.clone();
	let state = state.with_blob_backend(backend);
	World {
		dir,
		state,
		store,
		gate,
	}
}

/// What changes while a request waits.
#[derive(Debug, Clone, Copy)]
enum Change {
	Nothing,
	Revoke,
	Suspend,
	MoveToAnotherDomain,
}

impl Change {
	/// The key the change takes something from.
	fn secret(self) -> &'static str {
		match self {
			Change::MoveToAnotherDomain => CONFINED,
			_ => BOUND,
		}
	}

	fn apply(self, world: &World) {
		match self {
			Change::Nothing => {}
			Change::Revoke => {
				let mut keys = crate::api::ApiKeyStore::open(world.dir.path()).expect("key store");
				keys.remove("bound").expect("remove key");
				let text = std::fs::read_to_string(world.dir.path().join("api_keys.toml"))
					.expect("key file");
				world.state.api_keys().reload_from(&text).expect("reload");
			}
			Change::Suspend => {
				world.store.set_disabled("carol", true).expect("disable");
			}
			Change::MoveToAnotherDomain => {
				let mut moved = world.store.dynamic_account("carol").expect("carol");
				moved.addresses = vec!["carol@other.example".to_string()];
				world
					.store
					.replace_account("carol", moved, None)
					.expect("move");
			}
		}
	}
}

/// A body the test hands over once the server has started to read it.
struct Held {
	started: Option<tokio::sync::oneshot::Sender<()>>,
	piece: tokio::sync::oneshot::Receiver<Vec<u8>>,
	done: bool,
}

impl futures_core::Stream for Held {
	type Item = Result<axum::body::Bytes, std::io::Error>;

	fn poll_next(
		self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<Option<Self::Item>> {
		use std::task::Poll;
		let this = self.get_mut();
		if let Some(started) = this.started.take() {
			let _ = started.send(());
		}
		if this.done {
			return Poll::Ready(None);
		}
		Pin::new(&mut this.piece).poll(cx).map(|piece| {
			this.done = true;
			piece.ok().map(|bytes| Ok(axum::body::Bytes::from(bytes)))
		})
	}
}

/// The files under the blob directory.
fn stored_blobs(dir: &std::path::Path) -> usize {
	let mut count = 0;
	let mut pending = vec![dir.join("blobs")];
	while let Some(next) = pending.pop() {
		for entry in std::fs::read_dir(next).into_iter().flatten().flatten() {
			if entry.path().is_dir() {
				pending.push(entry.path());
			} else {
				count += 1;
			}
		}
	}
	count
}

fn upload_request(secret: &str, body: Body) -> Request<Body> {
	Request::builder()
		.method("POST")
		.uri("/jmap/upload/carol")
		.header(header::AUTHORIZATION, format!("Bearer {secret}"))
		.header(header::CONTENT_TYPE, "application/octet-stream")
		.body(body)
		.expect("request")
}

/// Upload with the body held back until `change` has been made.
async fn upload_while(world: &World, change: Change) -> StatusCode {
	let (started, reading) = tokio::sync::oneshot::channel();
	let (send, piece) = tokio::sync::oneshot::channel();
	let request = upload_request(
		change.secret(),
		Body::from_stream(Held {
			started: Some(started),
			piece,
			done: false,
		}),
	);
	let app = router(world.state.clone());
	let answer = tokio::spawn(async move { app.oneshot(request).await.expect("response") });
	reading.await.expect("the body was never read");
	change.apply(world);
	send.send(PAYLOAD.to_vec()).expect("send the body");
	answer.await.expect("the request task").status()
}

#[tokio::test]
async fn an_upload_is_served_when_nothing_changed_while_its_body_arrived() {
	let world = world();
	assert_eq!(upload_while(&world, Change::Nothing).await, StatusCode::OK);
	assert!(stored_blobs(world.dir.path()) > 0);
}

#[tokio::test]
async fn an_upload_stores_nothing_for_a_credential_that_lost_its_reach() {
	for change in [Change::Revoke, Change::Suspend, Change::MoveToAnotherDomain] {
		let world = world();
		let status = upload_while(&world, change).await;
		assert!(!status.is_success(), "{change:?}: {status}");
		assert_eq!(
			stored_blobs(world.dir.path()),
			0,
			"{change:?}: nothing stored"
		);
	}
}

/// Upload a blob, then download it while the blob store holds the read back
/// until `change` has been made; the status and the body.
async fn download_while(change: Change) -> (StatusCode, Vec<u8>) {
	let world = world();
	let response = router(world.state.clone())
		.oneshot(upload_request(BOUND, Body::from(PAYLOAD.to_vec())))
		.await
		.expect("upload");
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	let uploaded: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
	let blob = uploaded["blobId"].as_str().expect("blobId");
	let request = Request::builder()
		.uri(format!("/jmap/download/carol/{blob}/file.bin"))
		.header(header::AUTHORIZATION, format!("Bearer {}", change.secret()))
		.body(Body::empty())
		.expect("request");
	world.gate.armed.store(true, Ordering::SeqCst);
	let app = router(world.state.clone());
	let answer = tokio::spawn(async move { app.oneshot(request).await.expect("response") });
	tokio::time::timeout(Duration::from_secs(10), world.gate.entered.notified())
		.await
		.expect("the blob was never read");
	change.apply(&world);
	world.gate.release.add_permits(1);
	let response = answer.await.expect("the request task");
	let status = response.status();
	let body = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	(status, body.to_vec())
}

#[tokio::test]
async fn a_download_is_served_when_nothing_changed_while_the_blob_was_read() {
	let (status, body) = download_while(Change::Nothing).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body, PAYLOAD);
}

#[tokio::test]
async fn a_download_hands_nothing_to_a_credential_that_lost_its_reach() {
	for change in [Change::Revoke, Change::Suspend, Change::MoveToAnotherDomain] {
		let (status, body) = download_while(change).await;
		assert!(!status.is_success(), "{change:?}: {status}");
		assert!(
			!body.windows(PAYLOAD.len()).any(|window| window == PAYLOAD),
			"{change:?}: the payload was handed over"
		);
	}
}
