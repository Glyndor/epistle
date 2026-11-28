//! What the queue routes read: envelopes and never the message, and no more of
//! them than one request may.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;
use uuid::Uuid;

use crate::api::ApiState;
use crate::smtp::session::AcceptedMessage;

/// `read` and `write`, confined to `a.example`.
const TENANT_A: &str = "queue-bounds-tenant-a-secret";

struct World {
	dir: tempfile::TempDir,
	state: ApiState,
	spool: crate::storage::FsSpool,
}

impl World {
	/// Queue one message of `owner` for `recipients`.
	fn queue(&self, owner: &str, recipients: Vec<String>) -> Uuid {
		self.spool
			.store_owned(
				&AcceptedMessage {
					reverse_path: format!("ann@{owner}"),
					recipients,
					data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
					require_tls: false,
					mailbox: None,
					tlsrpt_verified: false,
					sender_verified: false,
					no_dsn: Vec::new(),
				},
				Some(owner),
				&BTreeMap::new(),
			)
			.expect("store")
	}

	/// Queue a message whose envelope is a little over half of the bytes one
	/// request reads, so a request reads two of them and no third.
	fn queue_large(&self, owner: &str) -> Uuid {
		let local = "r".repeat(1000);
		let count = crate::storage::MOST_QUEUE_BYTES / 2 / 1000 + 1;
		self.queue(owner, vec![format!("{local}@remote.example"); count])
	}

	fn file(&self, id: Uuid, extension: &str) -> std::path::PathBuf {
		self.dir.path().join(format!("spool/new/{id}.{extension}"))
	}
}

fn world() -> World {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().canonicalize().expect("canonical");
	let mut keys = crate::api::ApiKeyStore::open(&data_dir).expect("key store");
	keys.add(crate::api::ApiKey {
		label: "tenant-a".to_string(),
		hash: crate::api::api_keys::sha256_hash(TENANT_A),
		expires_at: None,
		ip_cidr: None,
		scopes: vec!["read".to_string(), "write".to_string()],
		grants: Vec::new(),
		domains: vec!["a.example".to_string()],
		account: None,
		auto_submitted: false,
	})
	.expect("add key");
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
		crate::storage::FsSpool::open(&data_dir).expect("spool"),
	)
	.with_directory(accounts.handle());
	let spool = crate::storage::FsSpool::open(&data_dir).expect("spool");
	World { dir, state, spool }
}

async fn call(
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
	let value = serde_json::from_slice(&bytes).unwrap_or_default();
	(status, value)
}

/// Walk the listing to its end: the ids of each page.
async fn walk(state: &ApiState, bearer: &str) -> Vec<Vec<String>> {
	let mut pages: Vec<Vec<String>> = Vec::new();
	let mut path = "/api/v1/queue".to_string();
	loop {
		let (status, page) = call(state, "GET", &path, bearer).await;
		assert_eq!(status, StatusCode::OK, "{path}");
		pages.push(
			page["entries"]
				.as_array()
				.expect("entries")
				.iter()
				.map(|entry| entry["id"].as_str().expect("id").to_string())
				.collect(),
		);
		assert!(pages.len() <= 10, "the walk does not end");
		match page["next_cursor"].as_str() {
			Some(cursor) => path = format!("/api/v1/queue?cursor={cursor}"),
			None => return pages,
		}
	}
}

/// A message that cannot be opened is listed and removed all the same: both
/// routes work from the envelope.
#[tokio::test]
async fn a_listing_and_a_removal_read_no_message() {
	let world = world();
	let id = world.queue("a.example", vec!["bob@remote.example".to_string()]);
	let message = world.file(id, "eml");
	std::fs::remove_file(&message).expect("remove the message");
	// The spool refuses to read through a link.
	std::os::unix::fs::symlink("nowhere", &message).expect("link");

	assert_eq!(walk(&world.state, TENANT_A).await, [vec![id.to_string()]]);

	let path = format!("/api/v1/queue/{id}");
	let (status, body) = call(&world.state, "DELETE", &path, TENANT_A).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert!(!world.file(id, "json").exists());
}

/// A page stops once it has read its bytes of envelope, and the pages after it
/// carry on: every entry once, in order.
#[tokio::test]
async fn a_listing_stops_when_its_bytes_are_spent_and_carries_on() {
	let world = world();
	let ids: Vec<String> = (0..3)
		.map(|_| world.queue_large("b.example").to_string())
		.collect();
	let mine = world
		.queue("a.example", vec!["bob@remote.example".to_string()])
		.to_string();
	let mut all = ids.clone();
	all.push(mine.clone());

	let pages = walk(&world.state, crate::api::tests::base::TOKEN.as_str()).await;
	assert_eq!(pages, [all[..2].to_vec(), all[2..].to_vec()]);

	// A confined key walks the same pages over entries it does not see.
	let pages = walk(&world.state, TENANT_A).await;
	assert_eq!(pages, [Vec::new(), vec![mine]]);
}

#[tokio::test]
async fn destinations_say_when_the_queue_is_larger_than_one_request_reads() {
	let world = world();
	let token = crate::api::tests::base::TOKEN.as_str();
	world.queue_large("b.example");
	world.queue_large("b.example");
	let (status, body) = call(&world.state, "GET", "/api/v1/queue/destinations", token).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["truncated"], false, "two entries fit: {body}");

	world.queue_large("b.example");
	let (status, body) = call(&world.state, "GET", "/api/v1/queue/destinations", token).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["truncated"], true, "a third is left unread: {body}");
}
