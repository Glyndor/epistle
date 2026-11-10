//! What a `GET` and a `PROPFIND` hold in memory is bounded.

use axum::http::StatusCode;

use crate::webdav::test_support::{send_as_alice, test_app};

/// The tree `alice` sees as `/`.
fn alice_root(dir: &std::path::Path) -> std::path::PathBuf {
	dir.join("accounts").join("alice").join("dav")
}

/// A file longer than a `PUT` may store is not read into memory: `413`, and a
/// file at the limit is still served.
#[tokio::test]
async fn get_of_a_file_past_the_put_cap_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send_as_alice(&app, "MKCOL", "/d", &[], b"").await;
	let root = alice_root(dir.path());
	let cap = super::PUT_BODY_LIMIT as u64;
	let at_cap = std::fs::File::create(root.join("d/at-cap.bin")).expect("create");
	at_cap.set_len(cap).expect("sparse");
	let past = std::fs::File::create(root.join("d/past-cap.bin")).expect("create");
	past.set_len(cap + 1).expect("sparse");
	let (status, body) = send_as_alice(&app, "GET", "/d/past-cap.bin", &[], b"").await;
	assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
	assert!(body.is_empty());
	let (status, body) = send_as_alice(&app, "GET", "/d/at-cap.bin", &[], b"").await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body.len() as u64, cap);
}

/// A `Depth: 1` listing too long for the reply budget is refused whole with
/// `507` and `number-of-matches-within-limits`; a small one still answers `207`.
#[tokio::test]
async fn propfind_listing_past_the_reply_budget_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = test_app(dir.path());
	send_as_alice(&app, "MKCOL", "/big", &[], b"").await;
	let big = alice_root(dir.path()).join("big");
	// Long names make each entry cost about 1 KiB: 30000 of them pass 24 MiB
	// while staying under the 50000 members a collection may hold.
	for n in 0..30_000 {
		let name = format!("{n:08}{}", "x".repeat(247));
		std::fs::File::create(big.join(name)).expect("create");
	}
	let depth = [("Depth", "1")];
	let (status, body) = send_as_alice(&app, "PROPFIND", "/big", &depth, b"").await;
	assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE);
	assert!(body.contains("number-of-matches-within-limits"));
	send_as_alice(&app, "MKCOL", "/small", &[], b"").await;
	send_as_alice(&app, "PUT", "/small/a.txt", &[], b"a").await;
	let (status, _) = send_as_alice(&app, "PROPFIND", "/small", &depth, b"").await;
	assert_eq!(status, StatusCode::MULTI_STATUS);
}
