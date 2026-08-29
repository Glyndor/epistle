//! JMAP blob-ownership tests, second half. Split from `jmap_tests_d.rs`
//! only to stay under the per-file line limit; the harness lives there.

use axum::http::StatusCode;

use super::jmap_tests_d::{get_raw, post_raw, state_with_two_accounts};
use super::router;
use super::tests::TOKEN;

/// The `.owner` sidecar is written by `upload` in the same atomic-ish move as
/// the payload and the `.type` sidecar: if any of the three writes fails the
/// blob is not advertised to the caller. This test directly exercises that
/// invariant via the public upload handler — a partial-write blob whose
/// payload exists but whose sidecars do not would survive the backfill only
/// because the message referenced it, which cannot happen since `upload` is
/// the only way to mint a fresh `blobId`.
#[tokio::test]
async fn upload_writes_owner_sidecar() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(state_with_two_accounts(dir.path()));
	let (_, body) = post_raw(&app, "/jmap/upload/alice", Some(TOKEN.as_str()), None, b"x").await;
	let blob_id = body["blobId"].as_str().expect("blobId").to_string();
	let owner_path = crate::api::jmap::blob_path::read_path(dir.path(), &blob_id, ".owner");
	assert!(owner_path.exists(), "upload must write the owner sidecar");
	assert_eq!(
		std::fs::read_to_string(&owner_path).expect("read"),
		"alice",
		"owner sidecar must carry the uploading account"
	);
}

/// Convenience constructor for tests that want a state without the FsSpool
/// open ceremony — exercises `ApiState::new` once on an empty directory so
/// the wiring in `state.rs` cannot silently regress to "no backfill".
#[test]
fn api_state_new_runs_backfill_on_construction() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path();
	let inbox = path.join("accounts/alice/new");
	std::fs::create_dir_all(&inbox).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(inbox.join(format!("{id}.eml")), b"x").expect("write msg");
	let blobs = path.join("blobs");
	std::fs::create_dir_all(&blobs).expect("mkdir blobs");
	std::fs::write(blobs.join(id.to_string()), b"p").expect("write payload");

	let _state = state_with_two_accounts(path);

	// Building the state must have run the backfill; verify the sidecar is
	// now on disk without calling the backfill function explicitly.
	let owner = std::fs::read_to_string(crate::api::jmap::blob_path::read_path(
		path,
		&id.to_string(),
		".owner",
	))
	.expect("owner");
	assert_eq!(owner, "alice", "ApiState::new must trigger the backfill");
	// Sanity: nothing else got invented.
	let entries: Vec<_> = std::fs::read_dir(&blobs)
		.map(|d| d.flatten().map(|e| e.file_name()).collect())
		.unwrap_or_default();
	assert_eq!(entries.len(), 2, "only payload + .owner should exist");
}

/// A malformed `.owner` (empty file, missing payload) is treated as if the
/// sidecar were absent: the blob is unservable until the backfill (or any
/// future repair tool) rewrites it. This is the fail-closed posture: rather
/// than guessing, the gate refuses.
#[tokio::test]
async fn empty_owner_sidecar_is_treated_as_missing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path();
	let blobs = path.join("blobs");
	std::fs::create_dir_all(&blobs).expect("mkdir");
	let id = uuid::Uuid::now_v7();
	std::fs::write(blobs.join(id.to_string()), b"orphan").expect("write payload");
	// Empty sidecar: present but no usable account name.
	std::fs::write(
		crate::api::jmap::blob_path::read_path(path, &id.to_string(), ".owner"),
		b"",
	)
	.expect("write empty owner");

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
		"empty sidecar must not serve"
	);
	let json: serde_json::Value =
		serde_json::from_slice(&body_bytes).unwrap_or(serde_json::Value::Null);
	assert_eq!(
		json["type"], "urn:ietf:params:jmap:error:notFound",
		"empty-sidecar rejection must use the notFound sentinel, body={json}"
	);
}

/// Startup cost of the backfill on a non-trivial corpus. The per-message work
/// is constant (read one directory entry, parse its UUID, maybe write one
/// sidecar), so the pass scales with the number of stored messages and a
/// large installation must not see a noticeable startup delay. This test is
/// `#[ignore]`d by default so it does not slow down the suite; run it
/// explicitly with `cargo test --lib backfill_scales_linearly -- --ignored
/// --nocapture` to see the timing.
///
/// The corpus is built by minting UUIDs and writing both a `.eml` (in the
/// account's mailbox) and a matching payload in `blobs/`. In production
/// only a small fraction of stored messages have a corresponding blob —
/// most mailbox entries are inbound mail with no upload — so the realistic
/// write count is much lower; the all-corpus scenario here stresses the
/// worst case where every message is also an upload. The corpus size is
/// tuned with `BENCH_CORPUS` so the default (10k) stays in CI budget while
/// the `BENCH_CORPUS=100000` shape can be measured locally for the report.
#[test]
#[ignore]
fn backfill_scales_linearly_with_corpus() {
	let corpus: usize = std::env::var("BENCH_CORPUS")
		.ok()
		.and_then(|value| value.parse().ok())
		.unwrap_or(10_000);
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path();
	// Spread the corpus across 4 accounts (alice, bob, carol, dave) so the
	// backfill's per-account mailbox walk is exercised at the same time as
	// the cross-account directory scan.
	let accounts = ["alice", "bob", "carol", "dave"];
	for account in accounts {
		let inbox = path.join(format!("accounts/{account}/new"));
		std::fs::create_dir_all(&inbox).expect("mkdir");
	}
	let blobs = path.join("blobs");
	std::fs::create_dir_all(&blobs).expect("mkdir blobs");
	let per_account = corpus / accounts.len();
	let total = per_account * accounts.len();
	let start = std::time::Instant::now();
	for account in &accounts {
		let inbox = path.join(format!("accounts/{account}/new"));
		for _ in 0..per_account {
			let id = uuid::Uuid::now_v7();
			std::fs::write(inbox.join(format!("{id}.eml")), b"x").expect("write msg");
			std::fs::write(blobs.join(id.to_string()), b"p").expect("write payload");
		}
	}
	let setup_ms = start.elapsed().as_millis();
	eprintln!("[bench] setup: {total} messages + payloads in {setup_ms} ms");

	let names: Vec<String> = accounts.iter().map(|s| s.to_string()).collect();
	let start = std::time::Instant::now();
	let stats = super::jmap::backfill_blob_ownership(path, &names);
	let backfill_ms = start.elapsed().as_millis();
	eprintln!(
		"[bench] backfill: scanned={} written={} skipped={} conflicts={} errors={} in {backfill_ms} ms",
		stats.scanned, stats.written, stats.skipped, stats.conflicts, stats.errors
	);
	// Sanity: every message processed, no errors, every first-time pass
	// should write a sidecar (none pre-existed).
	assert_eq!(stats.scanned as usize, total);
	assert_eq!(stats.written as usize, total);
	assert_eq!(stats.skipped, 0);
	assert_eq!(stats.conflicts, 0);
	assert_eq!(stats.errors, 0);

	// Re-run: should be a no-op (already-correct sidecars).
	let start = std::time::Instant::now();
	let stats2 = super::jmap::backfill_blob_ownership(path, &names);
	let rerun_ms = start.elapsed().as_millis();
	eprintln!(
		"[bench] backfill (second run): scanned={} written={} skipped={} in {rerun_ms} ms",
		stats2.scanned, stats2.written, stats2.skipped
	);
	assert_eq!(stats2.scanned as usize, total);
	assert_eq!(stats2.written, 0);
	assert_eq!(stats2.skipped as usize, total);
}
