//! Tests for the S3 backend. The suite stands up an axum process that mimics
//! enough of S3 to exercise every verb (PUT, GET, DELETE, LIST) and to
//! distinguish 200/204/404/401/403 the way S3 does. There is no real S3
//! here: every assertion observes the mock state, the bytes it received, and
//! the SigV4 headers attached to those bytes.
//!
//! The "control" tests guard the obvious regressions:
//! - `fs default does no network` (a config without `[storage.blobs]` keeps
//!   blobs on disk and never opens a socket); this lives in
//!   `lib.rs::tests` because the assertion is about wiring, not about S3
//!   internals.
//! - `signature_matches_aws_published_vector` (SigV4 against AWS's own
//!   `Task 3` reference vector, the same one [`crate::dns::providers::route53::tests`]
//!   uses); lives in `sigv4_tests.rs` so the SigV4 surface is testable in
//!   isolation from HTTP.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::*;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, put};

/// What the mock keeps in memory for one object.
#[derive(Clone)]
struct StoredObject {
	bytes: Vec<u8>,
}

#[derive(Default)]
struct MockState {
	objects: HashMap<String, StoredObject>,
	/// Captured headers from the most recent request: keys are lower-cased.
	last_headers: HeaderMap,
	/// Captured method from the most recent request, useful for tests that
	/// want to confirm the request verb.
	last_method: String,
	/// Captured query string (`?` excluded) from the most recent request.
	/// SigV4 signs the canonical query, so the test against the AWS vector
	/// reads from this rather than from the in-memory state.
	last_query: String,
	/// When `true`, `GET /<bucket>/<key>` returns 403 Forbidden rather than
	/// the usual 404/200 path. Used to assert that an `Auth` error is
	/// distinguished from "absent".
	forbid_bucket: bool,
}

type Shared = Arc<Mutex<MockState>>;

async fn put_object(
	State(state): State<Shared>,
	Path((_bucket, key)): Path<(String, String)>,
	headers: HeaderMap,
	body: axum::body::Bytes,
) -> StatusCode {
	let mut s = state.lock().unwrap();
	s.last_headers = headers.clone();
	s.last_method = "PUT".to_string();
	s.objects.insert(
		key,
		StoredObject {
			bytes: body.to_vec(),
		},
	);
	StatusCode::OK
}

async fn get_object(
	State(state): State<Shared>,
	Path((_bucket, key)): Path<(String, String)>,
	headers: HeaderMap,
) -> (StatusCode, axum::body::Bytes) {
	let mut s = state.lock().unwrap();
	s.last_headers = headers;
	s.last_method = "GET".to_string();
	if s.forbid_bucket {
		return (StatusCode::FORBIDDEN, axum::body::Bytes::new());
	}
	match s.objects.get(&key) {
		Some(obj) => (StatusCode::OK, axum::body::Bytes::from(obj.bytes.clone())),
		None => (StatusCode::NOT_FOUND, axum::body::Bytes::new()),
	}
}

async fn delete_object(
	State(state): State<Shared>,
	Path((_bucket, key)): Path<(String, String)>,
	headers: HeaderMap,
) -> StatusCode {
	let mut s = state.lock().unwrap();
	s.last_headers = headers;
	s.last_method = "DELETE".to_string();
	match s.objects.remove(&key) {
		Some(_) => StatusCode::NO_CONTENT,
		None => StatusCode::NOT_FOUND,
	}
}

async fn list_objects(
	State(state): State<Shared>,
	Path(_bucket): Path<String>,
	headers: HeaderMap,
	axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> (StatusCode, axum::Json<serde_json::Value>) {
	let mut s = state.lock().unwrap();
	s.last_headers = headers;
	s.last_method = "GET".to_string();
	s.last_query = query.unwrap_or_default();
	// Empty result for a freshly stood-up server; tests that exercise the
	// list path pre-populate `state.objects` before calling.
	let contents: Vec<serde_json::Value> = s
		.objects
		.keys()
		.map(|key| serde_json::json!({"Key": key}))
		.collect();
	(
		StatusCode::OK,
		axum::Json(serde_json::json!({
			"Contents": contents,
			"IsTruncated": false,
		})),
	)
}

async fn mock() -> (S3Backend, Shared) {
	mock_with(|_| {}).await
}

/// Build the mock and the backend; the closure may pre-populate the mock's
/// object store so the suite can assert on a non-empty list.
async fn mock_with(setup: impl FnOnce(&mut MockState)) -> (S3Backend, Shared) {
	let state: Shared = Arc::new(Mutex::new(MockState::default()));
	setup(&mut state.lock().unwrap());
	let app = Router::new()
		.route("/{bucket}/{*key}", put(put_object).delete(delete_object))
		.route("/{bucket}/{*key}", get(get_object))
		.route("/{bucket}/", get(list_objects).put(list_objects))
		.with_state(state.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let backend = S3Backend::new(
		format!("http://{addr}"),
		"mail".into(),
		"us-east-1".into(),
		"AKID".into(),
		// Generated at runtime: never put a real or example-publisher
		// AWS secret here, even in test code. The mock does not check
		// credentials, so any opaque string works.
		Uuid::now_v7().to_string(),
	);
	(backend, state)
}

fn id(tail: &str) -> Uuid {
	// v7-shaped id: timestamp-led, random tail. The host only sees the
	// `id` and `suffix` from the trait; this fixture pins a UUID that
	// survives the literal-vs-parsed round-trip. `tail` lands in the last
	// group (12 hex chars max) so callers stay within UUID format rules.
	let padded = format!("{tail:0>12}");
	let hex = padded[..12].to_string();
	let uuid = format!("0198f2c1-9a4b-7000-8000-{hex}");
	Uuid::parse_str(&uuid).expect("fixture")
}

/// The account partition most tests write into.
fn alice() -> crate::storage::BlobAccount {
	crate::storage::BlobAccount::new("alice").expect("alice")
}

#[tokio::test]
async fn put_then_get_round_trips_bytes() {
	let (backend, _state) = mock().await;
	let blob_id = id("0001aabb");
	backend
		.put(&alice(), blob_id, "", b"hello-blob")
		.await
		.expect("put");
	let read = backend.get(&alice(), blob_id, "").await.expect("get");
	assert_eq!(read, Some(b"hello-blob".to_vec()));
}

#[tokio::test]
async fn sidecar_put_lands_under_its_own_suffix() {
	// The upload handler writes `.type` and `.owner` sidecars with their
	// own suffixes; the mock's object-store keys are exactly those
	// suffixes, so the backend must keep them addressable independently.
	let (backend, state) = mock().await;
	let blob_id = id("0002ccdd");
	backend
		.put(&alice(), blob_id, "", b"payload")
		.await
		.expect("payload put");
	backend
		.put(&alice(), blob_id, ".type", b"text/plain")
		.await
		.expect("type put");
	backend
		.put(&alice(), blob_id, ".owner", b"alice")
		.await
		.expect("owner put");
	let s = state.lock().unwrap();
	assert!(s.objects.contains_key(&format!("accounts/alice/{blob_id}")));
	assert!(
		s.objects
			.contains_key(&format!("accounts/alice/{blob_id}.type"))
	);
	assert!(
		s.objects
			.contains_key(&format!("accounts/alice/{blob_id}.owner"))
	);
	assert_eq!(
		s.objects
			.get(&format!("accounts/alice/{blob_id}.type"))
			.unwrap()
			.bytes,
		b"text/plain".to_vec()
	);
	assert_eq!(
		s.objects
			.get(&format!("accounts/alice/{blob_id}.owner"))
			.unwrap()
			.bytes,
		b"alice".to_vec()
	);
}

#[tokio::test]
async fn get_of_an_absent_key_returns_none() {
	let (backend, _state) = mock().await;
	let blob_id = id("0003eeff");
	let read = backend.get(&alice(), blob_id, "").await.expect("get");
	assert_eq!(read, None, "absent object must be a clean `None`");
}

#[tokio::test]
async fn delete_absent_key_is_ok_so_caller_does_not_branch() {
	let (backend, _state) = mock().await;
	let blob_id = id("0004aabb");
	// Deleting something that was never written is a no-op (S3 returns 404
	// for `NoSuchKey`, which we map to `Ok(())`).
	let outcome = backend.delete(&alice(), blob_id, "").await;
	assert!(
		outcome.is_ok(),
		"delete of an absent key must be Ok: {outcome:?}"
	);
}

#[tokio::test]
async fn delete_present_key_actually_removes_it() {
	let (backend, state) = mock().await;
	let blob_id = id("0005ccdd");
	backend.put(&alice(), blob_id, "", b"x").await.expect("put");
	backend.delete(&alice(), blob_id, "").await.expect("delete");
	let s = state.lock().unwrap();
	assert!(!s.objects.contains_key(&format!("accounts/alice/{blob_id}")));
}

#[tokio::test]
async fn list_returns_every_payload_and_skips_sidecars() {
	let (backend, state) = mock_with(|s| {
		s.objects.insert(
			id("00060001").to_string(),
			StoredObject {
				bytes: b"a".to_vec(),
			},
		);
		s.objects.insert(
			format!("{}.type", id("00060001")),
			StoredObject {
				bytes: b"text/plain".to_vec(),
			},
		);
		s.objects.insert(
			format!("{}.owner", id("00060001")),
			StoredObject {
				bytes: b"alice".to_vec(),
			},
		);
		s.objects.insert(
			id("00060002").to_string(),
			StoredObject {
				bytes: b"b".to_vec(),
			},
		);
	})
	.await;
	let mut ids = backend.list().await.expect("list");
	ids.sort();
	let mut want = vec![id("00060001"), id("00060002")];
	want.sort();
	assert_eq!(ids, want, "sidecars must be skipped");
	// Sanity: nothing else landed in the mock besides the four we put.
	let s = state.lock().unwrap();
	assert_eq!(s.objects.len(), 4);
}

#[tokio::test]
async fn forbid_bucket_returns_blob_error_auth_not_none() {
	// A 403 from the bucket must be reported as `Auth`, never as "object
	// not found". Otherwise a server chasing a wrong bucket policy would
	// mistake a permissions mismatch for a clean download.
	let (backend, state) = mock_with(|s| {
		s.forbid_bucket = true;
		s.objects.insert(
			id("0007aabb").to_string(),
			StoredObject {
				bytes: b"x".to_vec(),
			},
		);
	})
	.await;
	let outcome = backend.get(&alice(), id("0007aabb"), "").await;
	assert!(
		matches!(outcome, Err(BlobError::Auth)),
		"403 must be Auth, got {outcome:?}"
	);
	let _ = state; // suppress unused
}

#[tokio::test]
async fn requests_carry_a_signed_authorization_header() {
	// Even without checking the exact signature bytes (the
	// `signature_matches_aws_published_vector` test in `sigv4_tests.rs` is
	// the load-bearing one), every request must carry an
	// `Authorization: AWS4-HMAC-SHA256 ...` header with the expected
	// credential scope and signed-headers list. This is the end-to-end
	// guard against a silent refactor that stops attaching the header at
	// all.
	let (backend, state) = mock().await;
	let blob_id = id("0008bbcc");
	backend.put(&alice(), blob_id, "", b"x").await.expect("put");
	let captured = {
		let s = state.lock().unwrap();
		(
			s.last_headers
				.get("authorization")
				.and_then(|v| v.to_str().ok())
				.map(str::to_string)
				.expect("an Authorization header is attached to every request"),
			s.last_headers
				.get("x-amz-content-sha256")
				.and_then(|v| v.to_str().ok())
				.map(str::to_string)
				.expect("x-amz-content-sha256"),
		)
	};
	let (auth, sha) = captured;
	assert!(
		auth.starts_with("AWS4-HMAC-SHA256 Credential=AKID/"),
		"{auth}"
	);
	assert!(
		auth.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"),
		"{auth}"
	);
	// x-amz-content-sha256 of `b"x"` matches the documented SHA-256.
	assert_eq!(
		sha,
		"2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
	);
}

#[tokio::test]
async fn unit_urlencode_round_trips_unreserved_characters() {
	for byte in b'A'..=b'Z' {
		assert_eq!(
			urlencode(&(byte as char).to_string()),
			(byte as char).to_string()
		);
	}
	assert_eq!(urlencode("hello-world"), "hello-world");
	assert_eq!(urlencode("a.b_c-d~e"), "a.b_c-d~e");
	// Reserved characters get percent-encoded.
	assert_eq!(urlencode("a/b"), "a%2Fb");
	assert_eq!(urlencode("a b"), "a%20b");
}

#[tokio::test]
async fn a_blob_is_found_only_in_its_own_partition() {
	let (backend, _state) = mock().await;
	let blob_id = id("0009aabb");
	backend
		.put(&alice(), blob_id, "", b"mine")
		.await
		.expect("put");
	let bob = crate::storage::BlobAccount::new("bob").expect("bob");
	let read = backend.get(&bob, blob_id, "").await.expect("get");
	assert_eq!(read, None, "alice's object must not be found as bob");
}

#[tokio::test]
async fn shared_keys_from_before_the_partitions_are_still_read_and_deleted() {
	let blob_id = id("000acafe");
	let (backend, state) = mock_with(|s| {
		s.objects.insert(
			blob_id.to_string(),
			StoredObject {
				bytes: b"older".to_vec(),
			},
		);
	})
	.await;
	let read = backend.get(&alice(), blob_id, "").await.expect("get");
	assert_eq!(read, Some(b"older".to_vec()));
	backend.delete(&alice(), blob_id, "").await.expect("delete");
	assert!(
		state.lock().unwrap().objects.is_empty(),
		"shared key removed"
	);
}

#[tokio::test]
async fn an_account_name_stays_one_key_segment_and_lists_back() {
	let (backend, state) = mock().await;
	let blob_id = id("000b0b0b");
	let spaced = crate::storage::BlobAccount::new("ann b?#").expect("plain component");
	backend.put(&spaced, blob_id, "", b"x").await.expect("put");
	let read = backend.get(&spaced, blob_id, "").await.expect("get");
	assert_eq!(read, Some(b"x".to_vec()));
	assert!(
		state
			.lock()
			.unwrap()
			.objects
			.contains_key(&format!("accounts/ann b?#/{blob_id}")),
		"the decoded key keeps the account as one segment"
	);
	assert_eq!(backend.list().await.expect("list"), vec![blob_id]);
}
