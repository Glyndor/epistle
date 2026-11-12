//! Uploads and the quota of the account, with several requests at once.

use super::base::{TOKEN, test_state};
use super::router;
use axum::http::StatusCode;

/// Uploads of one account at the same moment cannot all pass the quota check:
/// the check and the write are one step. One round rarely overlaps the two
/// requests, so the test runs many.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn uploads_at_the_same_time_stop_at_the_quota() {
	for round in 0..20 {
		let dir = tempfile::tempdir().expect("tempdir");
		std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
		let app = router(test_state(dir.path(), 0).with_quota(100));
		let mut set = tokio::task::JoinSet::new();
		for _ in 0..2 {
			let app = app.clone();
			set.spawn(async move {
				let request = axum::http::Request::builder()
					.method("POST")
					.uri("/jmap/upload/alice")
					.header(
						axum::http::header::AUTHORIZATION,
						format!("Bearer {}", TOKEN.as_str()),
					)
					.header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
					.body(axum::body::Body::from(vec![1u8; 80]))
					.expect("request");
				tower::ServiceExt::oneshot(app, request)
					.await
					.expect("response")
					.status()
			});
		}
		let mut stored = 0;
		while let Some(status) = set.join_next().await {
			match status.expect("upload") {
				StatusCode::OK => stored += 1,
				StatusCode::INSUFFICIENT_STORAGE => {}
				other => panic!("unexpected {other}"),
			}
		}
		assert_eq!(
			stored, 1,
			"round {round}: a quota of 100 holds one blob of 80, not {stored}"
		);
	}
}
