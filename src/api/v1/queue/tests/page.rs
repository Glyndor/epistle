//! The queue listing as a key confined to one tenant sees it: the cursor of
//! a page never names an entry of another tenant, and the listing walks to
//! the end and shows every entry of the tenant, once.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;
use uuid::{NoContext, Timestamp, Uuid};

use crate::api::ApiState;
use crate::smtp::session::AcceptedMessage;

/// `read` and `write`, confined to `a.example`.
const TENANT_A: &str = "queue-page-tenant-a-secret";

/// How many entries the other tenant has. One page reads at most a thousand
/// entries, so the entry this key can see is only found on the page after the
/// first one.
const FOREIGN: usize = 1000;

/// The second of the ids, so the ids of the queue are ordered as they are
/// written and the test knows which entry comes first.
const EPOCH: u64 = 1_700_000_000;

const MESSAGE: &str = "Subject: quarterly figures\r\nFrom: <ann@a.example>\r\nTo: bob@remote.example\r\n\r\ntop secret body text\r\n";

struct World {
	_dir: tempfile::TempDir,
	state: ApiState,
	/// The one entry the tenant can see.
	mine: Uuid,
	/// The entries of the other tenant, oldest first.
	theirs: Vec<Uuid>,
}

/// The id of the entry written `index` entries after the epoch.
fn id(index: usize) -> Uuid {
	Uuid::new_v7(Timestamp::from_unix(
		NoContext,
		EPOCH,
		(index as u32) * 1_000,
	))
}

/// Queue one message owned by `owner`, under the id the caller chose.
fn queue(spool: &crate::storage::FsSpool, id: Uuid, owner: &str) {
	spool
		.store_with(
			&AcceptedMessage {
				reverse_path: format!("ann@{owner}"),
				recipients: vec!["bob@remote.example".to_string()],
				data: MESSAGE.as_bytes().to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: false,
				no_dsn: Vec::new(),
			},
			id,
			&crate::storage::StoreOptions {
				account: None,
				extra: &BTreeMap::new(),
				owner: Some(owner),
				class: crate::evidence::MailClass::Personal,
				evidence: None,
				retain_days: 0,
			},
		)
		.expect("store");
}

fn key(label: &str, secret: &str, scopes: &[&str], domains: &[&str]) -> crate::api::ApiKey {
	crate::api::ApiKey {
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

fn world() -> World {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().canonicalize().expect("canonical");
	let spool = crate::storage::FsSpool::open(&data_dir).expect("spool");
	let mut theirs = Vec::new();
	for index in 0..FOREIGN {
		let entry = id(index);
		queue(&spool, entry, "b.example");
		theirs.push(entry);
	}
	let mine = id(FOREIGN);
	queue(&spool, mine, "a.example");
	let mut keys = crate::api::ApiKeyStore::open(&data_dir).expect("key store");
	keys.add(key(
		"tenant-a",
		TENANT_A,
		&["read", "write"],
		&["a.example"],
	))
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
		spool,
	)
	.with_directory(accounts.handle());
	World {
		_dir: dir,
		state,
		mine,
		theirs,
	}
}

async fn call(state: &ApiState, path: &str, bearer: &str) -> (StatusCode, serde_json::Value) {
	let request = Request::builder()
		.method("GET")
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

/// A key confined to one tenant walks the whole queue: no answer names an
/// entry of the other tenant, not even in the cursor, and the walk ends with
/// every entry of the tenant, once.
#[tokio::test]
async fn the_page_of_a_confined_key_never_names_another_tenants_entry() {
	let world = world();
	let mut cursor: Option<String> = None;
	let mut seen: Vec<String> = Vec::new();
	loop {
		let path = match &cursor {
			Some(cursor) => format!("/api/v1/queue?limit=2&cursor={cursor}"),
			None => "/api/v1/queue?limit=2".to_string(),
		};
		let (status, page) = call(&world.state, &path, TENANT_A).await;
		assert_eq!(status, StatusCode::OK, "{path}: {page}");
		let answer = page.to_string();
		for entry in &world.theirs {
			assert!(
				!answer.contains(&entry.to_string()),
				"the answer names the entry of another tenant: {answer}"
			);
		}
		for entry in page["entries"].as_array().expect("entries") {
			let id = entry["id"].as_str().expect("id").to_string();
			assert!(!seen.contains(&id), "the walk showed the entry {id} twice");
			seen.push(id);
		}
		match page["next_cursor"].as_str() {
			Some(next) => cursor = Some(next.to_string()),
			None => break,
		}
	}
	assert_eq!(seen, vec![world.mine.to_string()]);
	// A cursor the server did not issue is refused, not walked.
	let (status, body) = call(
		&world.state,
		"/api/v1/queue?cursor=q1.not-a-marker",
		TENANT_A,
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	assert_eq!(body["error"]["code"], "invalid_input");
}

/// A key with no confinement walks the queue as it always did: its cursor is
/// the id of the entry the page ended on.
#[tokio::test]
async fn the_page_of_an_unconfined_key_carries_the_id_of_an_entry() {
	let world = world();
	let (status, page) = call(
		&world.state,
		"/api/v1/queue?limit=2",
		crate::api::tests::base::TOKEN.as_str(),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{page}");
	let cursor = page["next_cursor"].as_str().expect("cursor");
	assert!(
		uuid::Uuid::parse_str(cursor).is_ok(),
		"the cursor of an unconfined key is an id: {cursor}"
	);
}
