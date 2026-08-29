//! JMAP blob-ownership tests: per-account download gate, `.owner` sidecar
//! enforcement, and startup backfill (RFC 8620 §6.1 / §6.2).

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

use super::router;
use super::tests::TOKEN;

use crate::storage::FsSpool;

/// Build an [`ApiState`] with two static accounts (alice and bob) so tests can
/// exercise the cross-account download gate.
pub(super) fn state_with_two_accounts(dir: &std::path::Path) -> crate::api::ApiState {
	let spool = FsSpool::open(dir).expect("open spool");
	let accounts = vec![
		crate::config::Account {
			name: "alice".to_string(),
			addresses: vec!["alice@example.org".to_string()],
			password_hash: Some("$argon2id$secret".to_string()),
			catch_all: Vec::new(),
			quota_bytes: None,
			forward: Vec::new(),
			forward_keep_local: true,
		},
		crate::config::Account {
			name: "bob".to_string(),
			addresses: vec!["bob@example.org".to_string()],
			password_hash: Some("$argon2id$secret".to_string()),
			catch_all: Vec::new(),
			quota_bytes: None,
			forward: Vec::new(),
			forward_keep_local: true,
		},
	];
	let store = Arc::new(
		crate::directory_store::AccountStore::open(
			dir,
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			accounts,
		)
		.expect("open store"),
	);
	crate::api::ApiState::new(
		&crate::smtp::auth::tests::hash(TOKEN.as_str()),
		dir.to_path_buf(),
		vec!["example.org".to_string()],
		store,
		spool,
	)
}

/// `POST` a raw body with an optional `Content-Type`, returning the status
/// and parsed JSON body.
pub(super) async fn post_raw(
	app: &Router,
	path: &str,
	token: Option<&str>,
	content_type: Option<&str>,
	body: &[u8],
) -> (StatusCode, serde_json::Value) {
	let mut builder = Request::builder().method("POST").uri(path);
	if let Some(token) = token {
		builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
	}
	if let Some(content_type) = content_type {
		builder = builder.header(header::CONTENT_TYPE, content_type);
	}
	let response = app
		.clone()
		.oneshot(builder.body(Body::from(body.to_vec())).expect("request"))
		.await
		.expect("response");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
	(status, json)
}

/// `GET` a raw path, returning the status and the response body bytes plus the
/// recorded `Content-Type`.
pub(super) async fn get_raw(
	app: &Router,
	path: &str,
	token: Option<&str>,
) -> (StatusCode, Option<String>, Vec<u8>) {
	let mut builder = Request::builder().method("GET").uri(path);
	if let Some(token) = token {
		builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
	}
	let response = app
		.clone()
		.oneshot(builder.body(Body::empty()).expect("request"))
		.await
		.expect("response");
	let status = response.status();
	let content_type = response
		.headers()
		.get(header::CONTENT_TYPE)
		.and_then(|value| value.to_str().ok())
		.map(str::to_string);
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	(status, content_type, bytes.to_vec())
}

/// ACCEPTANCE — account A uploads a blob and downloads it back successfully.
/// Pairs with the rejection test `bob_cannot_download_alice_blob` below.
#[tokio::test]
async fn alice_uploads_then_downloads_her_own_blob() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(state_with_two_accounts(dir.path()));
	let payload = b"alice-only attachment \x00\x01\x02";

	let (status, body) = post_raw(
		&app,
		"/jmap/upload/alice",
		Some(TOKEN.as_str()),
		Some("text/plain"),
		payload,
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let blob_id = body["blobId"].as_str().expect("blobId").to_string();

	let (status, content_type, got) = get_raw(
		&app,
		&format!("/jmap/download/alice/{blob_id}/x"),
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::OK,
		"alice should be able to read her own blob"
	);
	assert_eq!(content_type.as_deref(), Some("text/plain"));
	assert_eq!(got, payload, "downloaded bytes must match uploaded bytes");

	// The `.owner` sidecar carries the uploader's account name — this is what
	// the per-account gate reads, so verifying it here makes the control
	// explicit instead of relying on the test "just happening to work".
	let owner = super::jmap::read_blob_owner(dir.path(), &blob_id)
		.expect("upload must write the owner sidecar");
	assert_eq!(
		owner, "alice",
		"owner sidecar must record the uploading account"
	);
}

/// REJECTION — account B asks for an `blobId` uploaded by account A and gets
/// the JMAP `notFound` problem-details response. Pairs with the acceptance
/// test `alice_uploads_then_downloads_her_own_blob` above (same upload shape,
/// different account — exactly the boundary the gate enforces).
#[tokio::test]
async fn bob_cannot_download_alice_blob() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(state_with_two_accounts(dir.path()));
	let payload = b"alice-only attachment \x00\x01\x02";

	let (_, body) = post_raw(
		&app,
		"/jmap/upload/alice",
		Some(TOKEN.as_str()),
		Some("text/plain"),
		payload,
	)
	.await;
	let blob_id = body["blobId"].as_str().expect("blobId").to_string();

	// Bob asking for alice's blob must not see it.
	let (status, _, body_bytes) = get_raw(
		&app,
		&format!("/jmap/download/bob/{blob_id}/x"),
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::NOT_FOUND,
		"cross-account blob reads must be refused; got {} body={:?}",
		status,
		String::from_utf8_lossy(&body_bytes)
	);
	// The response body carries the JMAP `notFound` problem-details type — the
	// exact sentinel the gate promises, not a bare status code.
	let json: serde_json::Value =
		serde_json::from_slice(&body_bytes).unwrap_or(serde_json::Value::Null);
	assert_eq!(
		json["type"], "urn:ietf:params:jmap:error:notFound",
		"cross-account read must use the notFound sentinel, body={json}"
	);

	// Sanity: the blob still serves for alice (the gate did not delete it,
	// it only refused bob).
	let (status, _, _) = get_raw(
		&app,
		&format!("/jmap/download/alice/{blob_id}/x"),
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::OK,
		"alice's blob must still be servable"
	);
}

/// REJECTION — a blob without an `.owner` sidecar is never served. The gate
/// is the sidecar itself, not anything derived from the message store: the
/// shared `blobs/` pool is not partitioned per account, so the only thing
/// that tells one upload from another is the sidecar.
#[tokio::test]
async fn blob_without_owner_sidecar_is_not_served() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path();
	let blobs = path.join("blobs");
	std::fs::create_dir_all(&blobs).expect("mkdir");
	// A blob in the shared pool, but no `.owner` sidecar — simulates an
	// upload that predates the per-account gate. Its UUID is intentionally
	// NOT a message filename in any account's mailbox, so the download
	// route's `find_email_raw` lookup cannot return it; the test isolates
	// the `read_blob` gate.
	let id = uuid::Uuid::now_v7();
	std::fs::write(blobs.join(id.to_string()), b"orphan payload").expect("write");
	assert!(
		!crate::api::jmap::blob_path::read_path(path, &id.to_string(), ".owner")
			.expect("valid blob id")
			.exists(),
		"precondition: no owner sidecar before download"
	);

	let app = router(state_with_two_accounts(path));
	let (status, _, body_bytes) = get_raw(
		&app,
		&format!("/jmap/download/alice/{id}/x"),
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(
		status,
		StatusCode::NOT_FOUND,
		"a sidecar-less blob must 404"
	);
	let json: serde_json::Value =
		serde_json::from_slice(&body_bytes).unwrap_or(serde_json::Value::Null);
	assert_eq!(
		json["type"], "urn:ietf:params:jmap:error:notFound",
		"missing-sidecar rejection must use the notFound sentinel, body={json}"
	);
}

/// ACCEPTANCE — the startup backfill writes `.owner` for a blob whose
/// corresponding message already exists. Verified by reading the sidecar
/// directly: the download route would otherwise return the *message* bytes
/// for any UUID that is also an `.eml` filename (because `find_email_raw`
/// is checked before `read_blob`), so the sidecar-on-disk assertion is the
/// truthful signal that the backfill ran.
#[tokio::test]
async fn backfill_writes_owner_sidecar_for_referenced_blob() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path();
	let inbox = path.join("accounts/alice/new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	let raw = b"Subject: backfill\r\n\r\nbody\r\n";
	std::fs::write(inbox.join(format!("{id}.eml")), raw).expect("write");
	// Pre-existing blob, no `.owner` (the case the backfill migrates).
	let blobs = path.join("blobs");
	std::fs::create_dir_all(&blobs).expect("mkdir");
	std::fs::write(blobs.join(id.to_string()), b"pre-existing uploaded payload").expect("write");
	assert!(
		!crate::api::jmap::blob_path::read_path(path, &id.to_string(), ".owner")
			.expect("valid blob id")
			.exists()
	);

	// Run the backfill the way `ApiState::new` does.
	let stats = super::jmap::backfill_blob_ownership(path, &["alice".to_string()]);
	assert_eq!(
		stats.scanned, 1,
		"exactly the one stored message should be scanned"
	);
	assert_eq!(stats.written, 1, "the sidecar must have been written");
	assert_eq!(stats.skipped, 0);
	assert_eq!(stats.conflicts, 0);
	assert_eq!(stats.errors, 0);

	let owner_path = crate::api::jmap::blob_path::read_path(path, &id.to_string(), ".owner")
		.expect("valid blob id");
	assert!(owner_path.exists(), "backfill must materialise the sidecar");
	assert_eq!(
		std::fs::read_to_string(&owner_path).expect("read sidecar"),
		"alice",
		"backfill must record the message's account as the owner"
	);
}

/// IDEMPOTENCE — running the backfill a second time must not rewrite a sidecar
/// that already names the correct account. Verified by checking that the file
/// mtime is unchanged (the spec: "que no reescriba sidecars correctos").
#[tokio::test]
async fn backfill_is_idempotent_on_unchanged_ownership() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path();
	let inbox = path.join("accounts/alice/new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(inbox.join(format!("{id}.eml")), b"x").expect("write");
	let blobs = path.join("blobs");
	std::fs::create_dir_all(&blobs).expect("mkdir");
	std::fs::write(blobs.join(id.to_string()), b"p").expect("write");

	let stats1 = super::jmap::backfill_blob_ownership(path, &["alice".to_string()]);
	assert_eq!(stats1.written, 1);
	let owner_path = crate::api::jmap::blob_path::read_path(path, &id.to_string(), ".owner")
		.expect("valid blob id");
	let mtime1 = std::fs::metadata(&owner_path)
		.expect("sidecar after first run")
		.modified()
		.expect("mtime");

	// Touch the message so the directory entry's mtime moves but the sidecar
	// stays as the backfill wrote it: ensures the second run sees the
	// message again but still finds a correct sidecar (the idempotence path,
	// not the "already done" early-out).
	std::thread::sleep(std::time::Duration::from_millis(20));
	let _ = std::fs::metadata(inbox.join(format!("{id}.eml")))
		.expect("message")
		.modified()
		.expect("msg mtime");

	let stats2 = super::jmap::backfill_blob_ownership(path, &["alice".to_string()]);
	assert_eq!(stats2.scanned, 1, "the message must still be scanned");
	assert_eq!(
		stats2.written, 0,
		"second run must not rewrite a correct sidecar"
	);
	assert_eq!(
		stats2.skipped, 1,
		"second run must report the correct sidecar as already-correct"
	);
	assert_eq!(stats2.conflicts, 0);
	assert_eq!(stats2.errors, 0);

	let mtime2 = std::fs::metadata(&owner_path)
		.expect("sidecar after second run")
		.modified()
		.expect("mtime");
	assert_eq!(
		mtime1, mtime2,
		"correct sidecar must not be re-touched (mtime unchanged)"
	);
}

/// Backfill must NOT clobber a sidecar that names a different account: when
/// the same UUID appears as a stored message under two accounts (an anomaly,
/// but possible if a UUID collision ever happened) the existing sidecar wins.
/// Silently overwriting it would transfer ownership without warning.
#[tokio::test]
async fn backfill_does_not_overwrite_conflicting_sidecar() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path();
	let alice_inbox = path.join("accounts/alice/new");
	let bob_inbox = path.join("accounts/bob/new");
	std::fs::create_dir_all(&alice_inbox).expect("mkdir alice");
	std::fs::create_dir_all(&bob_inbox).expect("mkdir bob");
	// Same UUID used as a message filename under both accounts.
	let id = uuid::Uuid::now_v7();
	std::fs::write(alice_inbox.join(format!("{id}.eml")), b"a").expect("write a");
	std::fs::write(bob_inbox.join(format!("{id}.eml")), b"b").expect("write b");
	let blobs = path.join("blobs");
	std::fs::create_dir_all(&blobs).expect("mkdir blobs");
	std::fs::write(blobs.join(id.to_string()), b"shared").expect("write payload");
	// Pre-existing sidecar names bob. Alice's pass must not overwrite it.
	std::fs::write(
		crate::api::jmap::blob_path::read_path(path, &id.to_string(), ".owner")
			.expect("valid blob id"),
		b"bob",
	)
	.expect("write sidecar");

	let stats =
		super::jmap::backfill_blob_ownership(path, &["alice".to_string(), "bob".to_string()]);
	assert_eq!(
		stats.scanned, 2,
		"both accounts' messages should be scanned"
	);
	// Alice's pass: sidecar says bob, message says alice -> Conflict.
	// Bob's pass: sidecar says bob, message says bob -> AlreadyCorrect.
	assert_eq!(
		stats.conflicts, 1,
		"alice's pass must report the conflict, not overwrite"
	);
	assert_eq!(
		stats.written, 0,
		"no sidecar may be written when one already names a different account"
	);
	assert_eq!(stats.skipped, 1, "bob's pass must report AlreadyCorrect");
	assert_eq!(stats.errors, 0);
	// The pre-existing sidecar survives unchanged.
	let sidecar = std::fs::read_to_string(
		crate::api::jmap::blob_path::read_path(path, &id.to_string(), ".owner")
			.expect("valid blob id"),
	)
	.expect("read");
	assert_eq!(
		sidecar, "bob",
		"pre-existing owner sidecar must survive an attempted clobber"
	);
}

/// Backfill swallows a per-message filesystem error so one corrupt mailbox
/// does not abort the whole startup pass.
#[tokio::test]
async fn backfill_survives_per_mailbox_errors() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path();
	let inbox = path.join("accounts/alice/new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	// A non-UUID filename is silently skipped (the snapshot would have
	// rejected it anyway), and a UUID filename with a missing payload file
	// is treated as a no-op by `ensure_blob_owner`.
	let good = uuid::Uuid::now_v7();
	std::fs::write(inbox.join(format!("{good}.eml")), b"ok").expect("write good");
	std::fs::write(inbox.join("not-a-uuid.eml"), b"ignore").expect("write junk");
	let blobs = path.join("blobs");
	std::fs::create_dir_all(&blobs).expect("mkdir blobs");
	std::fs::write(blobs.join(good.to_string()), b"p").expect("write payload");

	let stats = super::jmap::backfill_blob_ownership(path, &["alice".to_string()]);
	assert_eq!(
		stats.errors, 0,
		"skipped junk files must not count as errors"
	);
	assert_eq!(stats.scanned, 1, "only the UUID-named message is scanned");
	assert_eq!(stats.written, 1);
}

/// The reclaim sweep drops `.owner` along with `.type` when it expires a
/// blob, so a sidecar can never outlive its payload.
#[test]
fn reclaim_blobs_drops_owner_sidecar_with_payload() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path();
	let blobs = path.join("blobs");
	std::fs::create_dir_all(&blobs).expect("mkdir");
	let id = uuid::Uuid::now_v7().to_string();
	std::fs::write(blobs.join(&id), b"old").expect("write payload");
	std::fs::write(
		crate::api::jmap::blob_path::read_path(path, &id.to_string(), ".type")
			.expect("valid blob id"),
		b"text/plain",
	)
	.expect("write type");
	std::fs::write(
		crate::api::jmap::blob_path::read_path(path, &id.to_string(), ".owner")
			.expect("valid blob id"),
		b"alice",
	)
	.expect("write owner");
	let old = std::time::SystemTime::now() - std::time::Duration::from_secs(48 * 3600);
	let f = std::fs::OpenOptions::new()
		.write(true)
		.open(blobs.join(&id))
		.expect("open");
	f.set_modified(old).expect("set mtime");

	let removed = super::jmap::reclaim_blobs(path, std::time::Duration::from_secs(24 * 3600));
	assert_eq!(removed, 1);
	assert!(!blobs.join(&id).exists(), "payload reclaimed");
	assert!(
		!crate::api::jmap::blob_path::read_path(path, &id.to_string(), ".type")
			.expect("valid blob id")
			.exists(),
		".type sidecar reclaimed"
	);
	assert!(
		!crate::api::jmap::blob_path::read_path(path, &id.to_string(), ".owner")
			.expect("valid blob id")
			.exists(),
		".owner sidecar must be reclaimed alongside its payload"
	);
}
