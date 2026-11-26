//! A frame whose uploaded blobs are still being read is checked again once
//! they have been: the credential that was good when the frame arrived has to
//! be good when it runs.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, header};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

use super::revoke::{CAROL, Client, ws_state};
use crate::api::{ApiState, router};
use crate::storage::{BlobAccount, BlobBackend, BlobError};

type Wait<'a, T> = Pin<Box<dyn Future<Output = Result<T, BlobError>> + Send + 'a>>;

/// The server's blob store, which can hold back the read of a payload: it
/// tells when one starts and waits to be let go.
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

/// `ws_state` with the gate in front of its blob store.
fn gated(
	dir: &std::path::Path,
) -> (
	ApiState,
	Arc<crate::directory_store::AccountStore>,
	Arc<Gate>,
) {
	let (state, store) = ws_state(dir);
	let gate = Arc::new(Gate {
		inner: Arc::clone(state.blob_backend()),
		armed: AtomicBool::new(false),
		entered: tokio::sync::Notify::new(),
		release: tokio::sync::Semaphore::new(0),
	});
	let backend: Arc<dyn BlobBackend> = gate.clone();
	(state.with_blob_backend(backend), store, gate)
}

async fn upload(state: &ApiState) -> String {
	let request = Request::builder()
		.method("POST")
		.uri("/jmap/upload/carol")
		.header(header::AUTHORIZATION, format!("Bearer {CAROL}"))
		.body(Body::from(vec![7u8; 600]))
		.expect("request");
	let response = router(state.clone())
		.oneshot(request)
		.await
		.expect("response");
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	let body: Value = serde_json::from_slice(&bytes).expect("json");
	body["blobId"].as_str().expect("blobId").to_string()
}

fn create_with(blob: &str) -> Value {
	json!({
		"@type": "Request",
		"id": "held",
		"using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
		"methodCalls": [["Email/set", {"accountId": "carol", "create": {"e": {
			"mailboxIds": {"INBOX": true},
			"from": [{"email": "carol@example.org"}],
			"to": [{"email": "bob@elsewhere.example"}],
			"subject": "held",
			"textBody": [{"partId": "t"}], "bodyValues": {"t": {"value": "see attached"}},
			"attachments": [{"blobId": blob, "type": "application/octet-stream", "name": "a.bin"}],
		}}}, "c1"]],
	})
}

/// The messages stored anywhere under carol's mailbox.
fn messages(dir: &std::path::Path) -> usize {
	let mut count = 0;
	let mut pending = vec![dir.join("accounts").join("carol")];
	while let Some(next) = pending.pop() {
		for entry in std::fs::read_dir(next).into_iter().flatten().flatten() {
			let path = entry.path();
			if path.is_dir() {
				pending.push(path);
			} else if path.extension().is_some_and(|kind| kind == "eml") {
				count += 1;
			}
		}
	}
	count
}

/// Send the frame, wait until its blob is being read, run `change`, let the
/// read finish; the socket, with the reply not yet taken.
async fn send_and_change(state: &ApiState, gate: &Gate, change: impl FnOnce()) -> Client {
	let blob = upload(state).await;
	let mut client = Client::open(state.clone(), CAROL).await;
	gate.armed.store(true, Ordering::SeqCst);
	client.send(&create_with(&blob)).await;
	tokio::time::timeout(Duration::from_secs(10), gate.entered.notified())
		.await
		.expect("the blob was never read");
	change();
	gate.release.add_permits(1);
	client
}

async fn assert_refused(client: &mut Client, what: &str) {
	let reply = client.next_json().await;
	assert_eq!(reply["@type"], "RequestError", "{what}: {}", reply["@type"]);
	assert_eq!(reply["requestId"], "held", "{what}");
	let (opcode, _) = client.next().await;
	assert_eq!(opcode, 8, "{what}: expected a close frame");
}

#[tokio::test]
async fn a_frame_runs_when_nothing_changed_while_its_blob_was_read() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (state, _store, gate) = gated(dir.path());
	let mut client = send_and_change(&state, &gate, || {}).await;
	let reply = client.next_json().await;
	assert!(
		reply["methodResponses"][0][1]["created"]["e"]["id"].is_string(),
		"{reply}"
	);
	assert_eq!(messages(dir.path()), 1);
}

#[tokio::test]
async fn suspending_the_account_while_a_blob_is_read_refuses_the_frame() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (state, store, gate) = gated(dir.path());
	let mut client = send_and_change(&state, &gate, || {
		store.set_disabled("carol", true).expect("disable");
	})
	.await;
	assert_refused(&mut client, "suspended").await;
	assert_eq!(messages(dir.path()), 0, "nothing was written");
}

#[tokio::test]
async fn revoking_the_key_while_a_blob_is_read_refuses_the_frame() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (state, _store, gate) = gated(dir.path());
	let mut client = send_and_change(&state, &gate, || {
		let mut keys = crate::api::ApiKeyStore::open(dir.path()).expect("key store");
		keys.remove("carol-key").expect("remove key");
		let text = std::fs::read_to_string(dir.path().join("api_keys.toml")).expect("keys");
		state.api_keys().reload_from(&text).expect("reload keys");
	})
	.await;
	assert_refused(&mut client, "revoked").await;
	assert_eq!(messages(dir.path()), 0, "nothing was written");
}
